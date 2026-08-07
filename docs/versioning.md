# Versioning and private releases

Both packages start at `0.1.0` and follow Semantic Versioning. A normal shared
release updates these files together:

1. `VERSION`;
2. `packages/django/pyproject.toml` and the Python `__version__`;
3. `packages/react/package.json` and `packages/react/package-lock.json`;
4. `CHANGELOG.md` and `packages/react/CHANGELOG.md`.

Run all checks, commit the release, then create a signed or annotated local tag:

```bash
git tag -a v0.1.0 -m "TriadCAPTCHA 0.1.0"
```

No release command in this repository publishes to PyPI/npm, pushes a tag, or
deploys an image. A maintainer must explicitly push the reviewed commit/tag to the
private remote.

## Upgrading an installation

Pin an immutable tag or commit. Read every intervening changelog entry, update both
packages, run `python manage.py migrate`, rebuild frontend assets, run Django checks
and application tests, then deploy. Roll out secret rotation separately from a
package upgrade so either change can be diagnosed and rolled back independently.

Because stock npm installs a Git dependency from the repository root rather than a
workspace subdirectory, private releases should create a React subtree ref:

```bash
git subtree split --prefix=packages/react -b release/react-0.1.0
git tag -a react-v0.1.0 release/react-0.1.0 -m "@triadcaptcha/react 0.1.0"
```

The tag is local until a maintainer explicitly pushes it. Consumers can then use
`npm install "git+ssh://git@HOST/ORG/triadcaptcha.git#react-v0.1.0"`.
