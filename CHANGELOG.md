# Changelog

## [0.4.0](https://github.com/specmon/specmon/compare/v0.3.0...v0.4.0) (2026-10-22)


### ⚠ BREAKING CHANGES

* **rule:** Macros now expand in trigger and hint annotations. Rename literal event functions or constructors that share a macro name to preserve their previous meaning.
* **monitor:** Premise variables keep their facts' values and types. A byte-equal event value no longer replaces them. A string field rejects a byte-valued premise variable.
* **monitor:** A failed evaluation or restriction ends only its branch. An event that no branch survives is a monitor violation with recorded reasons, so the violation hook and PID termination apply.
* **monitor:** Loading rejects Eq or Neq restrictions without two operands, evaluable functions or cat fields with invalid arities, variables that matching cannot bind, premises that cannot be parsed on their own, and PPEvent actions whose argument is not a pair.
* **parser:** Macro heads must be function calls whose parameters are distinct variables. Constant, nested or repeated parameters are rejected.
* **rule:** Models whose distinct source-rule names generate the same state-fact name now fail loading. Rename one of the reported rules.
* **monitor:** Loading rejects a model in which an epsilon rule has no linear premise, or has a premise that an epsilon step can produce: a conclusion of an epsilon rule, or of a decomposed rule whose end rule produces it.
* **monitor:** Standalone rewriting rejects alternatives with different output sequences, including a silent alternative. Use monitor -R to keep these alternatives as separate branches.
* **monitor:** Rewrite output must have a function call whose outer name is not a documented built-in. Models that emit such built-ins now fail loading or output processing.
* **term:** Invalid ground cat, and, or, xor or not expressions are evaluation errors. The names xor and not are reserved for the built-in operations.
* **term:** Integers are int64: out-of-range literals are parse errors, int fields are unsigned, and an int field without a width takes eight bytes, including as the last field of a cat. JSON constants keep their kind; legacy numbers with a fraction or exponent are rejected. Addition requires non-negative integers and fails on overflow.
* **cmd:** A monitor violation now prints the statistics on stdout and ends with "Error: monitor violation at event N: no applicable rule found <event>" instead of a fatal log line; `specmon rewrite` names the rejected event the same way. SIGINT and SIGTERM print "signal received, exiting" and exit with status 0, and a second signal ends SpecMon at once.

### Features

* **build:** Stamp the git revision into the version output ([#84](https://github.com/specmon/specmon/issues/84)) ([95b9d05](https://github.com/specmon/specmon/commit/95b9d0525f468c5455df7fcef212d1ea7da67918))
* **cmd:** Add on-violation hook ([78a8e2a](https://github.com/specmon/specmon/commit/78a8e2a9a9af6969422b5627fa64b1a774f1fb22))
* **cmd:** Report the reasons of failed rule candidates with a violation ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **cmd:** Terminate a given PID after a monitor violation ([78a8e2a](https://github.com/specmon/specmon/commit/78a8e2a9a9af6969422b5627fa64b1a774f1fb22))
* **monitor:** Label the allowed events of a pipeline rejection by side ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **rule:** Drop unused RHS facts and preserve computations ([#80](https://github.com/specmon/specmon/issues/80)) ([7fd7539](https://github.com/specmon/specmon/commit/7fd7539e488ad8c192df91a81766417a301b279b))
* **term:** Add xor and not and check built-in evaluation ([#85](https://github.com/specmon/specmon/issues/85)) ([076c3fd](https://github.com/specmon/specmon/commit/076c3fd1c9b3d1c042bee864bdbdfcac944a6fe3))


### Bug Fixes

* **monitor:** Bind premise variables from their facts ([#100](https://github.com/specmon/specmon/issues/100)) ([6d0ddb4](https://github.com/specmon/specmon/commit/6d0ddb46ae7197c63cb7256218b580bf76951feb))
* **monitor:** Check arities and variable binding on load ([#98](https://github.com/specmon/specmon/issues/98)) ([7f6d84b](https://github.com/specmon/specmon/commit/7f6d84b4fbbb379e2da9937f6001487ecc1f179f))
* **monitor:** Complete multi-trigger desugaring semantics ([#86](https://github.com/specmon/specmon/issues/86)) ([27a9c18](https://github.com/specmon/specmon/commit/27a9c18e7b66ecaa5222217d17619e8feb48cf3a))
* **monitor:** Explore every hint alternative ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **monitor:** Give each applicable epsilon rule its own successor ([#92](https://github.com/specmon/specmon/issues/92)) ([178fe90](https://github.com/specmon/specmon/commit/178fe9058ab49151fcef0e6d8b4ff72f8c5140ef))
* **monitor:** Keep rewrite branches paired with their core states ([#87](https://github.com/specmon/specmon/issues/87)) ([6e3ccc4](https://github.com/specmon/specmon/commit/6e3ccc46f9ad6b7c234f5d0689ffb2a2c8579c18))
* **monitor:** Keep rule candidate failures local to their branch ([#99](https://github.com/specmon/specmon/issues/99)) ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **monitor:** Narrow formatted premise candidates safely ([#104](https://github.com/specmon/specmon/issues/104)) ([d40ab10](https://github.com/specmon/specmon/commit/d40ab10016cfab928efa44b87e7999b22c444234))
* **monitor:** Preserve epsilon action representations ([178fe90](https://github.com/specmon/specmon/commit/178fe9058ab49151fcef0e6d8b4ff72f8c5140ef))
* **monitor:** Recompute continuations for each hint binding ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **monitor:** Reject ambiguous and invalid rewrite output ([#91](https://github.com/specmon/specmon/issues/91)) ([6be1e4e](https://github.com/specmon/specmon/commit/6be1e4ee0077153778e988166da123f33fa370c2))
* **monitor:** Reject built-in names on emitted event calls ([6be1e4e](https://github.com/specmon/specmon/commit/6be1e4ee0077153778e988166da123f33fa370c2))
* **monitor:** Reject premises that cannot be parsed on their own ([7f6d84b](https://github.com/specmon/specmon/commit/7f6d84b4fbbb379e2da9937f6001487ecc1f179f))
* **monitor:** Store persistent facts once and count linear copies ([#97](https://github.com/specmon/specmon/issues/97)) ([377073b](https://github.com/specmon/specmon/commit/377073b3cdfd5cb1b3715fd88f5729a6fea34100))
* **monitor:** Try configurations in the order of their hashes ([a5d775f](https://github.com/specmon/specmon/commit/a5d775f135986f6974e6beaf5405b8d0f58f31b0))
* **parser:** Expand macros by parameter substitution ([#95](https://github.com/specmon/specmon/issues/95)) ([d17fede](https://github.com/specmon/specmon/commit/d17fede0e43142ac679b497cb41880a53267eaf8))
* **rule:** Carry public variables through split-rule chains ([#90](https://github.com/specmon/specmon/issues/90)) ([e571f5f](https://github.com/specmon/specmon/commit/e571f5f6f253d7f219c3be07924f8e2f7c791848))
* **rule:** Expand macros in trigger and hint annotations ([#101](https://github.com/specmon/specmon/issues/101)) ([a3cac57](https://github.com/specmon/specmon/commit/a3cac5782bc80ceb9d79bee707cb9a991a1352da))
* **rule:** Fuse eligible translation boundaries ([#93](https://github.com/specmon/specmon/issues/93)) ([c112e33](https://github.com/specmon/specmon/commit/c112e33ee81e0ba3a08667b259094226bcdffe0f))
* **rule:** Include persistence kind in fact equality ([377073b](https://github.com/specmon/specmon/commit/377073b3cdfd5cb1b3715fd88f5729a6fea34100))
* **rule:** Keep generated split states distinct ([#94](https://github.com/specmon/specmon/issues/94)) ([2d957cd](https://github.com/specmon/specmon/commit/2d957cd23d09b737b92a41e84d5a7824a896cccf))
* **rule:** Keep the source rule unchanged in the end rule ([c112e33](https://github.com/specmon/specmon/commit/c112e33ee81e0ba3a08667b259094226bcdffe0f))
* **rule:** Match start rules only to their own generated rules ([c112e33](https://github.com/specmon/specmon/commit/c112e33ee81e0ba3a08667b259094226bcdffe0f))
* **term:** Keep bindings consistent across arguments ([#96](https://github.com/specmon/specmon/issues/96)) ([568dd94](https://github.com/specmon/specmon/commit/568dd945f7a8ff5fca8385c2fcccf8ab2cc27cd2))
* **term:** Use exact int64 integers and JSON constant kinds ([#83](https://github.com/specmon/specmon/issues/83)) ([0a076ac](https://github.com/specmon/specmon/commit/0a076ac315feb12d0c541c540159849387fe1b09))


### Performance Improvements

* **cmd:** Buffer consumed-event output ([6e3ccc4](https://github.com/specmon/specmon/commit/6e3ccc46f9ad6b7c234f5d0689ffb2a2c8579c18))
* **monitor:** Prefilter large fact buckets by constant arguments ([#89](https://github.com/specmon/specmon/issues/89)) ([d7f8d30](https://github.com/specmon/specmon/commit/d7f8d306708f86f7c7fe8674d5d6d48fd691c0bb))
* **monitor:** Reduce rewrite pipeline overhead ([6e3ccc4](https://github.com/specmon/specmon/commit/6e3ccc46f9ad6b7c234f5d0689ffb2a2c8579c18))

## [0.3.0](https://github.com/specmon/specmon/compare/v0.2.0...v0.3.0) (2026-09-27)


### Features

* **parser:** Support boolean operators in #ifdef ([#64](https://github.com/specmon/specmon/issues/64)) ([d739f9b](https://github.com/specmon/specmon/commit/d739f9be9b18ace986af8597392b72fc15102830))
* **rule:** Add name generator for consistent term naming ([#60](https://github.com/specmon/specmon/issues/60)) ([78d323e](https://github.com/specmon/specmon/commit/78d323e5cf4164c8cea6f3195bb92b180526b434))


### Bug Fixes

* **ci:** Setup pnpm before Node.js in docs workflow ([#67](https://github.com/specmon/specmon/issues/67)) ([1539fe8](https://github.com/specmon/specmon/commit/1539fe81aeb4835111983002671a01568fee4c62))
* **data,term:** Handle hash collisions and make Binding.Equal symmetric ([#69](https://github.com/specmon/specmon/issues/69)) ([a25586b](https://github.com/specmon/specmon/commit/a25586b862c48c2f320ca96de6db9618afb6972e))


### Performance Improvements

* **monitor:** Index the conflict set and cap duplicate expansion ([#73](https://github.com/specmon/specmon/issues/73)) ([654d301](https://github.com/specmon/specmon/commit/654d301a99fc54dd9c7f9215855fbb552d9c4928))
* **monitor:** Rework conflict-set matching and fact storage ([#74](https://github.com/specmon/specmon/issues/74)) ([07d6b4c](https://github.com/specmon/specmon/commit/07d6b4c5bc89f9624b88636522b0686919423b9e))
* **term,rule:** Pre-allocate Vars and fast-path SubstBinding ([#70](https://github.com/specmon/specmon/issues/70)) ([ca4a979](https://github.com/specmon/specmon/commit/ca4a979248bd25baf96de6ede1838e1a7663c239))


### Reverts

* **data,term:** Hash collisions and symmetric Binding.Equal ([#69](https://github.com/specmon/specmon/issues/69)) ([#71](https://github.com/specmon/specmon/issues/71)) ([907b880](https://github.com/specmon/specmon/commit/907b880da5bb1bc643dcb97ad3debef46d350b3d))

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
