package client

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/caarlos0/log"
	"github.com/charmbracelet/x/exp/ordered"
	"github.com/google/go-github/v61/github"
	"github.com/goreleaser/goreleaser/pkg/config"
	"github.com/goreleaser/goreleaser/pkg/context"
	"golang.org/x/oauth2"
)

const DefaultGitHubDownloadURL = "https://github.com"

type githubClient struct {
	client *github.Client
}

func (r Repo) String() string {
	if r.Owner == "" && r.Name == "" {
		return ""
	}
	return r.Owner + "/" + r.Name
}

type Repo struct {
	Owner         string
	Name          string
	Branch        string
	GitURL        string
	GitSSHCommand string
	PrivateKey    string
}

// NewGitHubReleaseNotesGenerator returns a GitHub client that can generate
// changelogs.
func NewGitHubClient(ctx *context.Context, token string) (*github.Client, error) {
	return newGitHub(ctx, token)
}

// newGitHub returns a github client implementation.
func newGitHub(ctx *context.Context, token string) (*github.Client, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)

	httpClient := oauth2.NewClient(ctx, ts)
	base := httpClient.Transport.(*oauth2.Transport).Base
	if base == nil || reflect.ValueOf(base).IsNil() {
		base = http.DefaultTransport
	}
	// nolint: gosec
	base.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: ctx.Config.GitHubURLs.SkipTLSVerify,
	}
	base.(*http.Transport).Proxy = http.ProxyFromEnvironment
	httpClient.Transport.(*oauth2.Transport).Base = base

	client := github.NewClient(httpClient)

	// TODO: Add back overriding the github client api (ChaosInTheCRD)

	return client, nil
}

func (c *githubClient) checkRateLimit(ctx *context.Context) {
	limits, _, err := c.client.RateLimit.Get(ctx)
	if err != nil {
		log.Warn("could not check rate limits, hoping for the best...")
		return
	}
	if limits.Core.Remaining > 100 { // 100 should be safe enough
		return
	}
	sleep := limits.Core.Reset.UTC().Sub(time.Now().UTC())
	if sleep <= 0 {
		// it seems that sometimes, after the rate limit just reset, it might
		// still get <100 remaining and a reset time in the past... in such
		// cases we can probably sleep a bit more before trying again...
		sleep = 15 * time.Second
	}
	log.Warnf("token too close to rate limiting, will sleep for %s before continuing...", sleep)
	time.Sleep(sleep)
	c.checkRateLimit(ctx)
}

// getDefaultBranch returns the default branch of a github repo
func (c *githubClient) getDefaultBranch(ctx *context.Context, repo Repo) (string, error) {
	c.checkRateLimit(ctx)
	p, res, err := c.client.Repositories.Get(ctx, repo.Owner, repo.Name)
	if err != nil {
		log := log.WithField("projectID", repo.String())
		if res != nil {
			log = log.WithField("statusCode", res.StatusCode)
		}
		log.
			WithError(err).
			Warn("error checking for default branch")
		return "", err
	}
	return p.GetDefaultBranch(), nil
}

func headString(base, head Repo) string {
	return strings.Join([]string{
		ordered.First(head.Owner, base.Owner),
		ordered.First(head.Name, base.Name),
		ordered.First(head.Branch, base.Branch),
	}, ":")
}

func (c *githubClient) getPRTemplate(ctx *context.Context, repo Repo) (string, error) {
	content, _, _, err := c.client.Repositories.GetContents(
		ctx, repo.Owner, repo.Name,
		".github/PULL_REQUEST_TEMPLATE.md",
		&github.RepositoryContentGetOptions{
			Ref: repo.Branch,
		},
	)
	if err != nil {
		return "", err
	}
	return content.GetContent()
}

const prFooter = "###### Automated with VexCTL"

func (c *githubClient) OpenPullRequest(
	ctx *context.Context,
	base, head Repo,
	title string,
	draft bool,
) error {
	c.checkRateLimit(ctx)
	base.Owner = ordered.First(base.Owner, head.Owner)
	base.Name = ordered.First(base.Name, head.Name)
	if base.Branch == "" {
		def, err := c.getDefaultBranch(ctx, base)
		if err != nil {
			return err
		}
		base.Branch = def
	}
	tpl, err := c.getPRTemplate(ctx, base)
	if err != nil {
		log.WithError(err).Debug("no pull request template found...")
	}
	if len(tpl) > 0 {
		log.Info("got a pr template")
	}

	log := log.
		WithField("base", headString(base, Repo{})).
		WithField("head", headString(base, head)).
		WithField("draft", draft)
	log.Info("opening pull request")
	pr, res, err := c.client.PullRequests.Create(
		ctx,
		base.Owner,
		base.Name,
		&github.NewPullRequest{
			Title: github.String(title),
			Base:  github.String(base.Branch),
			Head:  github.String(headString(base, head)),
			Body:  github.String(strings.Join([]string{tpl, prFooter}, "\n")),
			Draft: github.Bool(draft),
		},
	)
	if err != nil {
		if res.StatusCode == http.StatusUnprocessableEntity {
			log.WithError(err).Warn("pull request validation failed")
			return nil
		}
		return fmt.Errorf("could not create pull request: %w", err)
	}
	log.WithField("url", pr.GetHTMLURL()).Info("pull request created")
	return nil
}

func (c *githubClient) SyncFork(ctx *context.Context, head, base Repo) error {
	branch := base.Branch
	if branch == "" {
		def, err := c.getDefaultBranch(ctx, base)
		if err != nil {
			return err
		}
		branch = def
	}
	res, _, err := c.client.Repositories.MergeUpstream(
		ctx,
		head.Owner,
		head.Name,
		&github.RepoMergeUpstreamRequest{
			Branch: github.String(branch),
		},
	)
	if res != nil {
		log.WithField("merge_type", res.GetMergeType()).
			WithField("base_branch", res.GetBaseBranch()).
			Info(res.GetMessage())
	}
	return err
}

func (c *githubClient) CreateFile(
	ctx *context.Context,
	commitAuthor config.CommitAuthor,
	repo Repo,
	content []byte,
	path,
	message string,
) error {
	c.checkRateLimit(ctx)
	defBranch, err := c.getDefaultBranch(ctx, repo)
	if err != nil {
		return fmt.Errorf("could not get default branch: %w", err)
	}

	branch := repo.Branch
	if branch == "" {
		branch = defBranch
	}

	options := &github.RepositoryContentFileOptions{
		Committer: &github.CommitAuthor{
			Name:  github.String(commitAuthor.Name),
			Email: github.String(commitAuthor.Email),
		},
		Content: content,
		Message: github.String(message),
	}

	// Set the branch if we got it above...otherwise, just default to
	// whatever the SDK does auto-magically
	if branch != "" {
		options.Branch = &branch
	}

	log.
		WithField("repository", repo.String()).
		WithField("branch", repo.Branch).
		WithField("file", path).
		Info("pushing")

	if defBranch != branch && branch != "" {
		_, res, err := c.client.Repositories.GetBranch(ctx, repo.Owner, repo.Name, branch, 100)
		if err != nil && (res == nil || res.StatusCode != http.StatusNotFound) {
			return fmt.Errorf("could not get branch %q: %w", branch, err)
		}

		if res.StatusCode == http.StatusNotFound {
			defRef, _, err := c.client.Git.GetRef(ctx, repo.Owner, repo.Name, "refs/heads/"+defBranch)
			if err != nil {
				return fmt.Errorf("could not get ref %q: %w", "refs/heads/"+defBranch, err)
			}

			if _, _, err := c.client.Git.CreateRef(ctx, repo.Owner, repo.Name, &github.Reference{
				Ref: github.String("refs/heads/" + branch),
				Object: &github.GitObject{
					SHA: defRef.Object.SHA,
				},
			}); err != nil {
				rerr := new(github.ErrorResponse)
				if !errors.As(err, &rerr) || rerr.Message != "Reference already exists" {
					return fmt.Errorf("could not create ref %q from %q: %w", "refs/heads/"+branch, defRef.Object.GetSHA(), err)
				}
			}
		}
	}

	file, _, res, err := c.client.Repositories.GetContents(
		ctx,
		repo.Owner,
		repo.Name,
		path,
		&github.RepositoryContentGetOptions{
			Ref: branch,
		},
	)
	if err != nil && (res == nil || res.StatusCode != http.StatusNotFound) {
		return fmt.Errorf("could not get %q: %w", path, err)
	}

	options.SHA = github.String(file.GetSHA())
	if _, _, err := c.client.Repositories.UpdateFile(
		ctx,
		repo.Owner,
		repo.Name,
		path,
		options,
	); err != nil {
		return fmt.Errorf("could not update %q: %w", path, err)
	}
	return nil
}

func githubErrLogger(resp *github.Response, err error) *log.Entry {
	requestID := ""
	if resp != nil {
		requestID = resp.Header.Get("X-GitHub-Request-Id")
	}
	return log.WithField("request-id", requestID).WithError(err)
}

// ErrNoMilestoneFound is an error when no milestone is found.
type ErrNoMilestoneFound struct {
	Title string
}

func (e ErrNoMilestoneFound) Error() string {
	return fmt.Sprintf("no milestone found: %s", e.Title)
}

// RetriableError is an error that will cause the action to be retried.
type RetriableError struct {
	Err error
}

func (e RetriableError) Error() string {
	return e.Err.Error()
}
