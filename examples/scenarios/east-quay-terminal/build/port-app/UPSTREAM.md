# Upstream source provenance

Base application: `PratibhaAwasthi/Shipping-Port-Management-Sys`
Upstream commit reviewed: `67da2e92975995810714e18b77469df8f6152a78` (2023-03-20).

For this benchmark integration, the `frontEnd/` and `backEnd/` PHP files were
merged as directed by the upstream README, `testCase/test.php` was installed as
the include expected by `database.php`, and hard-coded database connection
literals were replaced with `DB_HOST`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`
environment lookups. The image uses a local MariaDB service and synthetic seed
data. No upstream external database endpoint or credentials are used.

Integration hardening: the upstream `shipupdate.php` form and its
`shipstatus.php` handler were not role-protected, although they mutate vessel
status and are not part of the carrier workflow. Both are limited to the
operations role in this range so the legacy direct status-update path cannot
bypass clearance, yard dispatch, and the independent broker-observation
evidence path.
