# Development Guide Lines

TO-DO

## Tag and Release a new version

Activate the GH-workflow with a tag and push

Example:

```shell
git tag -s v0.0.3-SNAPSHOT -m 'v0.0.3-SNAPSHOT'
git push origin tag v0.0.3
```

Currently only publishing to GitHub-packages

## Run same code quality tests locally as in CI

```shell
./developement/codequality.sh
```

## Generate Javadocs

```shell
mvn javadoc:javadoc
<browser> target/reports/apidocs/index.html
```
