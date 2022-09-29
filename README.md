# vexctl: A tool to make VEX work

`vexctl` is a tool to apply and attest VEX (Vulnerability Exploitability eXchange) 
data. Its purpose is to "turn off" alerts of vulnerabilities known not to affect
a product.

VEX can be though as a "negative security advisory". Using VEX, software authors
can communicate to their users that a vulnerable component has no security
implications for their product.

## Operational Model

To achieve its mission, `vexctl` has two main modes of operation. One
helps the user create VEX statements, the second applies the VEX data 
to scanner results.

### 1. Create VEX Statements

VEX data can be created to a file on disk or it can be captured in a
signed attestation which can be attached to a container image.

The data is generated from a known rule set (the Golden Data) which is
reused and reapplied to new releases of the same project.

#### Generation Examples

```
# Attest and attach vex statements in mydata.vex.json to a container image:
vexctl attest --attach --sign mydata.vex.json cgr.dev/image@sha256:e4cf37d568d195b4..

```

### 2. VEXing a Results Set

Using statements in a VEX document or from an attestation, `vexctl` will filter
security scanner results to remove _vexed out_ entries.

#### Filtering Examples

```
# From a VEX file:
vexctl filter scan_results.sarif.json vex_data.csaf


# From a stored VEX attestation:
vectl filter scan_results.sarif.json cgr.dev/image@sha256:e4cf37d568d195b4b5af4c36a...

```

The output from both examples willl the same SARIF results data
without those ulnerabilities stated as not explitable:

```json
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "fullName": "Trivy Vulnerability Scanner",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "name": "Trivy",
          "rules": [

```

We support results files in SARIF for now. We plan to add support for the
propietary formats of the most popular scanners.

### Multiple VEX Files 

Assessing impact is process that takes time. VEX is designed to
communicate with users as time progresses. An example timeline may look like
this:

1. A project becomes aware of `CVE-2022-12345`, associated to on of its components.
2. Developers issue a VEX data file with a status of `under_investigation` to
inform their users they are aware of the CVE but are checking what impact it has.
3. After investigation, the developers determine the CVE has no impact 
in their project because the vulnerable function in the component is never executed.
4. They issue a second VEX document with a status of `not_affected` and using
the `vulnerable_code_not_in_execute_path` justification.

`vectl` will read all the documents in cronological order and "replay" the
known impacts statuses the order they were found, effectively computing the 
`not_affected` status.

If a sarif report is VEX'ed with `vexctl` any entries alerting of CVE-2022-12345
will be filtered out.

## Build vexctl

To build `vexctl` clone this repository and run simply run make.

```bash
git clone git@github.com:chainguard-dev/vex.git
cd vex
make

./vexctl version
 _   _  _____ __   __ _____  _____  _
| | | ||  ___|\ \ / //  __ \|_   _|| |
| | | || |__   \ V / | /  \/  | |  | |
| | | ||  __|  /   \ | |      | |  | |
\ \_/ /| |___ / /^\ \| \__/\  | |  | |____
 \___/ \____/ \/   \/ \____/  \_/  \_____/
vexctl: A tool for working with VEX data

GitVersion:    devel
GitCommit:     unknown
GitTreeState:  unknown
BuildDate:     unknown
GoVersion:     go1.19
Compiler:      gc
Platform:      linux/amd64

```