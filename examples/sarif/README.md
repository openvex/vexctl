# SARIF Examples

This directory contains examples of SARIF output when scanning a container image
with popular container image scanners. These files are for testing and development
purposes.

If you'd like OpenVEX to support another SAIRF flavor, please open a PR
to add a file here and file an issue (or feel free to contribute it yourself!).
To get a sample SARIF doc, just point your favorite scanner to this version of
the nginx image and send us the results:

`  sha256:13d22ec63300e16014d4a42aed735207a8b33c223cff19627dd3042e5a10a3a0   `

## Using These Examples

You can test the filtering feature of `vexctl` using these files. There are a couple
of OpenVEX examples to test:

| Filename | Details |
| --- | --- | 
| sample-1statement.openvex.json | OpenVEX document, one statement filtering CVE-2023-27103 |
| sample-2vulns.openvex.json | Document with two statements filterin CVE-2023-27103 and CVE-2007-5686 |
| sample-history.openvex.json | Sample document with more statements forming a VEX history of CVE-2023-27103 |

All the SARIF documents in this directory contain results for the vulnerabilities
in the VEX documents.

You can inspect the number of vulnerabilities in the reports by counting the 
`results` array:

```
cat examples/sarif/nginx-grype.sarif.json | jq '.runs[0].results | length'
99
```

To filter the SARIF reports, run `vexctl` feeding it a report and a VEX file:

```
vexctl filter examples/sarif/nginx-grype.sarif.json examples/sarif/sample-1statement.openvex.json
```

This invocation will print to STDERR the filtered document without the results
marked in the OpenVEX documents as `fixed` or `not_affected`. If you count the
results, there should be one less from the previous count of 99:

```
vexctl filter \
   examples/sarif/nginx-grype.sarif.json \
   examples/sarif/sample-1statement.openvex.json | jq '.runs[0].results | length'
```
