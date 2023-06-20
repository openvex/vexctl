# CSAF Examples

This directory is intended to contain CSAF files to test the OpenVEX tooling
capabilities to read CSAF VEX. On the long run, as the feature matures, we
should write some tests to ensure we are ingesting CSAF properly.

## Ingesting CSAF Documents

`vexctl` should be able to detect and read VEX statements in CSAF documents.
The easiest way to test is to invoke it to `vexctl merge` just one CSAF document,
this should return an OpenVEX document created from the data in the CSAF file:

```bash
vexctl merge examples/csaf/csaf.json 
```

### Output:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "merged-vex-23b3bef63c834f02772204d8c823c5c7d35db12b31518b3b111752b3f991769a",
  "author": "Unknown Author",
  "role": "Document Creator",
  "timestamp": "2023-06-09T12:01:32.239990099-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": "CVE-2009-4487",
      "timestamp": "2022-03-03T11:00:00.000Z",
      "products": [
        "pkg:generic/component1@1.3.4"
      ],
      "status": "not_affected",
      "action_statement": "Class with vulnerable code was removed before shipping."
    }
  ]
}
```

`vexctl merge` can also can read VEX data from documents in different formats
and compose a single document with statements coming from all documents. Using
the example files we can create a new document from our example CSAF file and
a sample OpenVEX document:

```bash
vexctl merge examples/csaf/csaf.json examples/csaf/openvex.json
```

### Output:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "merged-vex-d036fc7d69d1dddc641ab6f19e604be821fef5c9b2db00e0ed6bffe5ab9c470e",
  "author": "Unknown Author",
  "role": "Document Creator",
  "timestamp": "2023-06-19T17:27:53.725858678-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": "CVE-2009-4487",
      "timestamp": "2022-03-03T11:00:00.000Z",
      "products": [
        "pkg:generic/component1@1.3.4"
      ],
      "status": "not_affected",
      "action_statement": "Class with vulnerable code was removed before shipping."
    },
    {
      "vulnerability": "CVE-2014-123456",
      "timestamp": "2023-01-08T18:02:03.647Z",
      "products": [
        "pkg:generic/component2@2.39.0-r1"
      ],
      "status": "fixed"
    }
  ]
}

```
