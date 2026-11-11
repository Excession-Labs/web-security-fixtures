#!/bin/sh
# Recorded psql commands. verify.py creates and deletes the cluster; the socket
# directory and port below refer to the recorded run and no longer exist.
# Cluster: initdb -U postgres -A trust; postgres -k /tmp/exl-rls-_t1hrrai -p 53847 -c listen_addresses=
# m1_vulnerable: setup and policies in m1_vulnerable-setup.txt
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m1_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices WHERE tenant_id = '"'"'acme'"'"' ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m1_vulnerable
# m1_fixed: setup and policies in m1_fixed-setup.txt
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m1_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices WHERE tenant_id = '"'"'acme'"'"' ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m1_fixed
# m2_vulnerable: setup and policies in m2_vulnerable-setup.txt
echo 'SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = '"'"'invoices'"'"';
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m2_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m2_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_owner -d m2_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m2_vulnerable
# m2_fixed: setup and policies in m2_fixed-setup.txt
echo 'SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = '"'"'invoices'"'"';
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m2_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m2_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_owner -d m2_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m2_fixed
# m3_vulnerable: setup and policies in m3_vulnerable-setup.txt
echo 'SELECT policyname, cmd, with_check FROM pg_policies WHERE tablename = '"'"'invoices'"'"' AND cmd <> '"'"'SELECT'"'"' ORDER BY policyname;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (5, '"'"'globex'"'"', 999);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET tenant_id = '"'"'globex'"'"' WHERE id = 1;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (6, '"'"'acme'"'"', 10);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET amount = 300 WHERE id = 2;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (7, '"'"'acme'"'"', -5);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET tenant_id = '"'"'globex'"'"';
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_vulnerable
echo 'SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m3_vulnerable
# m3_fixed: setup and policies in m3_fixed-setup.txt
echo 'SELECT policyname, cmd, with_check FROM pg_policies WHERE tablename = '"'"'invoices'"'"' AND cmd <> '"'"'SELECT'"'"' ORDER BY policyname;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (5, '"'"'globex'"'"', 999);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET tenant_id = '"'"'globex'"'"' WHERE id = 1;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (6, '"'"'acme'"'"', 10);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET amount = 300 WHERE id = 2;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (7, '"'"'acme'"'"', -5);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET tenant_id = '"'"'globex'"'"';
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3_fixed
echo 'SELECT id, tenant_id, amount FROM invoices ORDER BY id;
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U postgres -d m3_fixed
# m3c_vulnerable: setup and policies in m3c_vulnerable-setup.txt
echo 'SET app.tenant_id = '"'"'acme'"'"';
INSERT INTO invoices VALUES (5, '"'"'globex'"'"', 999);
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3c_vulnerable
echo 'SET app.tenant_id = '"'"'acme'"'"';
UPDATE invoices SET tenant_id = '"'"'globex'"'"';
' | /opt/homebrew/bin/psql -X -a -h /tmp/exl-rls-_t1hrrai -p 53847 -U app_user -d m3c_vulnerable
