# mrclean: A tool to work with VEX

MrClean is a tool to apply and attest VEX (Vulnerability Exploitability eXchange) 
data. Its purpose is to "turn off alerts" of vulnerability data known not to affect
a product.

VEX can be though as a "negative security advisory". Using VEX,software authors
can communicate to their users that a vulnerable component has no security implications
in their product.

## Operational Model

To achieve its mission, MrClean has two main modes of operation. One
helps the user create VEX documents, the second applies the VEX data 
to scanner results.

### 1. Create VEX Statements

VEX data can be created to a file on disk or it can be
captured in an attestation attached to a container image.

The data is generated from a known rule set which can
be reused and reapplied to new releases of the same project.

#### Generation Examples

```
# Attest and attach vex statements to a container image:
mrclean attest --rules=mydata.vex.json cgr.dev/image@sha256:e4cf37d568d195b4b5af4c36a6ac50bdd6916cbbc442f2f70a377973a3530894

# Write VEX data to disk:
mrclean generate --rules=mydata.vex.json > vex.json

```

### 2. VEXing a Results Set

By applying the statements in a VEX document, MrClean will filter security scanner results to remove _vexed out_ entries.

#### Examples

```
# From a VEX file:
mrclean vex scan_results.sarif.json vex_data.csaf.


# From a stored VEX attestation:
mrclean vex scan_results.sarif.json --image=cgr.dev/image@sha256:e4cf37d568d195b4b5af4c36a6ac50bdd6916cbbc442f2f70a377973a3530894

# Output in both cases is the sarif results without known vulnerabilities:
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

We support SARIF results for now, we have plans to handle the propietary formats of the most popular scanners.

VEXing a results set means applying one or more VEX files.
MrClean will sort them in cronological order
and "replay" the known impacts in the order they were 
found.