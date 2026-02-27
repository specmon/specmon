# Changelog

## [0.2.0](https://github.com/specmon/specmon/compare/v0.1.0...v0.2.0) (2026-02-27)


### ⚠ BREAKING CHANGES

* **parser:** All specification files must now use double quotes for the `role` attribute value.

### Features

* **cmd:** Implement concurrent server for event input ([#26](https://github.com/specmon/specmon/issues/26)) ([05e6a95](https://github.com/specmon/specmon/commit/05e6a95f6158940250b273a8fb4521ea47c8bd39))
* **dev:** Add Nix flake for reproducible environment ([#9](https://github.com/specmon/specmon/issues/9)) ([9f6753f](https://github.com/specmon/specmon/commit/9f6753fd37c35c1d5bd078979d661c1a434f0ad1))
* **monitor:** Add integrated rewrite mode with pipeline architecture ([#30](https://github.com/specmon/specmon/issues/30)) ([6db8f74](https://github.com/specmon/specmon/commit/6db8f7449ed7f9edf1a82b96f301a219c4d2e4d5))
* **monitor:** Optimize conflict set implementation for performance ([#27](https://github.com/specmon/specmon/issues/27)) ([5dedfff](https://github.com/specmon/specmon/commit/5dedfff89547f361d73153d7fa175c53e2354c5c))
* **parser:** Add Tamarin preprocessor support ([#28](https://github.com/specmon/specmon/issues/28)) ([5ef42ea](https://github.com/specmon/specmon/commit/5ef42eacb873ef073ab769808d58da6f84b9be58))
* **rewrite:** Add command to rewrite event traces ([#8](https://github.com/specmon/specmon/issues/8)) ([4e9e98c](https://github.com/specmon/specmon/commit/4e9e98c025789b3241a0dce5b24eabd95f27d2d7))
* **rule:** Consider terms in actions for rule translation ([#15](https://github.com/specmon/specmon/issues/15)) ([7055177](https://github.com/specmon/specmon/commit/70551777cb33eb81d23cf67a9b592e12e109d8e9)), closes [#1](https://github.com/specmon/specmon/issues/1)
* **term:** Add reverse function for data manipulation ([#24](https://github.com/specmon/specmon/issues/24)) ([e8c56cf](https://github.com/specmon/specmon/commit/e8c56cfc7ef7b05ffaad2ed513e4e4452913419f))
* **term:** Add slice function for data manipulation ([#16](https://github.com/specmon/specmon/issues/16)) ([cc15cc6](https://github.com/specmon/specmon/commit/cc15cc6a18814e2e2fad28e1255a2c909e89ae86)), closes [#3](https://github.com/specmon/specmon/issues/3)


### Bug Fixes

* **ci:** Correct Nix flake description ([#52](https://github.com/specmon/specmon/issues/52)) ([9350bcd](https://github.com/specmon/specmon/commit/9350bcd67d6bb378b366b40c8925e5288ea22efd))
* **cmd:** Use pointer receivers for command configs ([#10](https://github.com/specmon/specmon/issues/10)) ([d5732fe](https://github.com/specmon/specmon/commit/d5732fe0d93dd7159ea51cb1e0ac476ea4be91d6))
* **docs:** Add pnpm workspace packages entry ([#45](https://github.com/specmon/specmon/issues/45)) ([f1d839f](https://github.com/specmon/specmon/commit/f1d839f16e19a5a2fd0efc915944ce9cf3ab23e7))
* **monitor:** Allow other rules when restriction check fails ([#39](https://github.com/specmon/specmon/issues/39)) ([0f0d16f](https://github.com/specmon/specmon/commit/0f0d16ff3a3217c110ba6c018b889d5d45360cd4))
* **monitor:** Prevent duplicate fact consumption in conflictSet ([#34](https://github.com/specmon/specmon/issues/34)) ([62c3988](https://github.com/specmon/specmon/commit/62c3988379aee2fc6a3ed0db37f3162c8e07fc46)), closes [#22](https://github.com/specmon/specmon/issues/22)
* **monitor:** Use original event time for rewritten events ([#11](https://github.com/specmon/specmon/issues/11)) ([8a8e08c](https://github.com/specmon/specmon/commit/8a8e08cc815b52f189a33c83a41860c69589a9c9))
* **parser:** Require double quotes for role attribute ([#13](https://github.com/specmon/specmon/issues/13)) ([e287115](https://github.com/specmon/specmon/commit/e2871150bc1a1358b14e3cfdc9ef2730dae9eced))
* **parser:** Require uppercase fact identifiers for facts ([#40](https://github.com/specmon/specmon/issues/40)) ([4be730e](https://github.com/specmon/specmon/commit/4be730eee004b20084fc1087bbf414a53da7ab21))
* **README:** Update logo in README to correct alignment ([#49](https://github.com/specmon/specmon/issues/49)) ([92c916b](https://github.com/specmon/specmon/commit/92c916bfe295531c6dfe22bb2558e973bcc0afd0))
* **rule:** Add missing integration test file ([#33](https://github.com/specmon/specmon/issues/33)) ([562f45b](https://github.com/specmon/specmon/commit/562f45bc1fb858f9ea2fa38ed8d4ca348fe26815))
* **rule:** Include public LHS variables in decomposed state facts ([#38](https://github.com/specmon/specmon/issues/38)) ([b4b2d12](https://github.com/specmon/specmon/commit/b4b2d121d6774e94cae0bb0f3801fd74beefba57))
* **rule:** Recursively expand formats in facts ([#14](https://github.com/specmon/specmon/issues/14)) ([bc304f8](https://github.com/specmon/specmon/commit/bc304f875a986a07e2da98a2b068aa009396337c))
* **rule:** Safely concatenate fact slices in translation ([#17](https://github.com/specmon/specmon/issues/17)) ([951b6e8](https://github.com/specmon/specmon/commit/951b6e8ad5045ee3b9f875736ae57d6727ce5cf9))
* **rule:** Skip decomposition for rules with existing triggers or hints ([#29](https://github.com/specmon/specmon/issues/29)) ([10dbc8c](https://github.com/specmon/specmon/commit/10dbc8ce1086315f390abb8e189714136b197a80)), closes [#25](https://github.com/specmon/specmon/issues/25)
* **rule:** Use LHS variables in subterm facts ([#20](https://github.com/specmon/specmon/issues/20)) ([ca7e977](https://github.com/specmon/specmon/commit/ca7e9770fc2973de2f2156f5c23a6de86ec9af42))
* **term:** Enforce exact byte length in format parsing ([#36](https://github.com/specmon/specmon/issues/36)) ([4f547af](https://github.com/specmon/specmon/commit/4f547af1695e6cd768895e54f401e4a8c458bf4e))


### Performance Improvements

* **term:** Optimize unification performance ([#37](https://github.com/specmon/specmon/issues/37)) ([7aab825](https://github.com/specmon/specmon/commit/7aab825fd00da15f3d03fc8a720f70b2d0d19576))

## [0.1.0](https://github.com/specmon/specmon/releases/tag/v0.1.0) (2025-01-16)

Initial public release of SpecMon, a runtime monitor for formal specifications
using multiset-rewrite rules.
