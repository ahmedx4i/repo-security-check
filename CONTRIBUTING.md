# Contributing

Thanks for helping improve Repo Security Check.

## Guidelines

1. Keep checks defensive and local by default.
2. Do not add functionality intended to exploit systems or extract secrets.
3. Include tests for each behavior change.
4. Preserve the dependency-free design unless a dependency clearly improves safety.

## Run tests

    python -m pip install -e .
    python -m unittest discover -s tests
