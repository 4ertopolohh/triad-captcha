# Compatibility policy

The initial release targets the following ranges:

| Component | Declared range | CI / recommended use |
| --- | --- | --- |
| Python | `>=3.10` | 3.10 through 3.14, subject to the selected Django release |
| Django | `>=4.2,<6.2` | CI: 4.2 legacy, 5.2 LTS, 6.0, and 6.1 |
| React | `>=18.2,<20` | React 18.3 and current React 19 |
| TypeScript | `>=5.4` | package emits declarations and a modern ESM bundle; CI uses 5.9 |
| ALTCHA Python | `>=2.1.0,<3` | PoW v2 API; 2.0.x is explicitly excluded |
| `altcha-lib` | `^2.3.2` | PoW v2 worker solver |
| Redis server | 7.x | Compose pins the 7.4 major/minor line |
| PostgreSQL | supported by host Django | demo uses PostgreSQL 17 |

Django 4.2 ended upstream security support on 7 April 2026. Compatibility is
retained to make migrations possible, but new production deployments should use
Django 5.2 LTS (security support through April 2028) or a current supported
feature release. Django 6.x requires Python 3.12 or newer.

React 18.3 is deliberately included because the React team describes it as the
bridge release that warns about React 19 changes. The SDK uses only APIs shared by
React 18 and 19 and declares React as a peer dependency.

Sources checked before implementation:

- [Django supported versions and roadmap](https://www.djangoproject.com/download/)
- [Django Python compatibility FAQ](https://docs.djangoproject.com/en/dev/faq/install/)
- [React 19 stable announcement](https://react.dev/blog/2024/12/05/react-19)
- [React 19 upgrade guide and React 18.3 guidance](https://react.dev/blog/2024/04/25/react-19-upgrade-guide)
- [ALTCHA server integration](https://altcha.org/docs/v2/server-integration/)
- [ALTCHA PoW v2 design and recommended PBKDF2 parameters](https://altcha.org/docs/v2/proof-of-work-captcha/)
- [Official ALTCHA Python library](https://github.com/altcha-org/altcha-lib-py)
- [Official ALTCHA JS library](https://github.com/altcha-org/altcha-lib-js)
- [ALTCHA security advisory](https://altcha.org/security-advisory/)

Support means the package test matrix passes. It does not extend upstream security
support. Patch versions should be kept current, and new Django/React major or LTS
versions are added only after CI and demo validation.

ALTCHA Python 2.0.x is not supported because the upstream advisory describes a
PoW v2 fallback-verification bypass fixed in 2.1.0. Dependency resolvers must not
override this lower bound.
