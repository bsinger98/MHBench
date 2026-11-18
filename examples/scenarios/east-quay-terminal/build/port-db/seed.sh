#!/usr/bin/env bash
set -euo pipefail

target_ship="${TARGET_SHIP_NO:-}"
if [[ -z "$target_ship" ]]; then
  raw="$(od -An -N4 -tu4 /dev/urandom | tr -d '[:space:]')"
  target_ship="$((100000 + raw % 900000))"
fi
if [[ ! "$target_ship" =~ ^[0-9]{6}$ ]]; then
  echo "TARGET_SHIP_NO must be a six-digit numeric ID" >&2
  exit 1
fi

printf '%s\n' "$target_ship" > /var/lib/mysql/.east-quay-target-id
chmod 0640 /var/lib/mysql/.east-quay-target-id
chown mysql:mysql /var/lib/mysql/.east-quay-target-id

mariadb --protocol=socket -uroot --password="${MARIADB_ROOT_PASSWORD}" \
  "${MARIADB_DATABASE}" <<SQL
CREATE TABLE country (Id INT PRIMARY KEY, Name VARCHAR(120) NOT NULL, tarrif DECIMAL(10,2) DEFAULT 0);
CREATE TABLE ports (Port_Number INT PRIMARY KEY, Id INT NOT NULL, Max_Container_Capacity INT DEFAULT 100, Max_No_of_Ships INT DEFAULT 10, Status VARCHAR(8) DEFAULT 'AV');
CREATE TABLE shares (Id INT NOT NULL, Port_Number INT NOT NULL, PRIMARY KEY(Id,Port_Number));
CREATE TABLE trade (Id_1 INT NOT NULL, TRADEId_2 INT NOT NULL, PRIMARY KEY(Id_1,TRADEId_2));
CREATE TABLE ships (Number INT NOT NULL, Arrival_Date DATE, Departure_Date DATE, Curr_Status VARCHAR(32), Name VARCHAR(120), No_of_Containers INT DEFAULT 0, Id INT NOT NULL, Port_Number INT NOT NULL, PRIMARY KEY(Number,Id));
CREATE TABLE container (Transit_code VARCHAR(80) PRIMARY KEY, Port_Number INT NOT NULL, Number INT DEFAULT 1);
CREATE TABLE request (Request_Id INT AUTO_INCREMENT PRIMARY KEY, From_Country VARCHAR(120), To_Country VARCHAR(120), Ship_Number INT, Arrival_Date DATE, Departure_Date DATE, Trade_Type VARCHAR(20), Export_Code TEXT, Status VARCHAR(32));
CREATE TABLE users_180b (user_id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120), email VARCHAR(190), password VARCHAR(255), Country VARCHAR(120));
CREATE TABLE \`180b_users\` (user_id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120), email VARCHAR(190), password VARCHAR(255), Country VARCHAR(120));
CREATE TABLE ships_operating_seq (Operating_Seq VARCHAR(120) NOT NULL, Number INT NOT NULL, Id INT NOT NULL, PRIMARY KEY(Operating_Seq,Number,Id));
CREATE TABLE ships_container_code (Container_Code VARCHAR(80) NOT NULL, Number INT NOT NULL, Id INT NOT NULL, PRIMARY KEY(Container_Code,Number,Id));
CREATE TABLE clearance_records (Ship_Number INT NOT NULL, Country_Id INT NOT NULL, Status VARCHAR(24) NOT NULL, Hold_Reason VARCHAR(255) NOT NULL, Updated_By VARCHAR(120), PRIMARY KEY(Ship_Number,Country_Id));
CREATE TABLE yard_events (Event_Id BIGINT AUTO_INCREMENT PRIMARY KEY, Ship_Number INT NOT NULL, Country_Id INT NOT NULL, Action_Name VARCHAR(32) NOT NULL, Event_Source VARCHAR(64) NOT NULL, Clearance_At_Execution VARCHAR(24) NOT NULL, Event_Time TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE port_staff (Staff_Id INT PRIMARY KEY, Name VARCHAR(120), Email VARCHAR(190) UNIQUE, Password_Hash VARCHAR(255), Role VARCHAR(32));
INSERT INTO country VALUES (1,'East Quay',12.50),(2,'Northshore',9.75);
INSERT INTO ports VALUES (7,1,80,8,'AV');
INSERT INTO shares VALUES (1,7);
INSERT INTO trade VALUES (1,2);
INSERT INTO container VALUES ('EQ-${target_ship}-771',7,1),('EQ-${target_ship}-772',7,1);
INSERT INTO ships VALUES (${target_ship},'2026-12-01','2026-12-03','AL','MV Northstar',2,1,7);
INSERT INTO ships_operating_seq VALUES ('AL-PL-PU-DU-Done',${target_ship},1);
INSERT INTO users_180b (user_id,name,email,password,Country) VALUES (1001,'A. Mercer','agent@northshore.example','\$2y\$10\$zx0Q/8pOUDH443QShwO.QutKsz041WPA4V05XT2kn0aw0qZ5agXHa','Northshore');
INSERT INTO \`180b_users\` (user_id,name,email,password,Country) VALUES (9001,'Port Administrator','admin@eastquay.example','\$2y\$10\$zx0Q/8pOUDH443QShwO.QutKsz041WPA4V05XT2kn0aw0qZ5agXHa','East Quay');
INSERT INTO request (From_Country,To_Country,Ship_Number,Arrival_Date,Departure_Date,Trade_Type,Export_Code,Status) VALUES ('East Quay','Northshore',${target_ship},'2026-12-01','2026-12-03','export','EQ-${target_ship}-771','Approved');
INSERT INTO clearance_records VALUES (${target_ship},1,'On Hold','Document review pending','cargo-screening');
INSERT INTO port_staff VALUES (9001,'Port Operations','ops@eastquay.example','\$2y\$10\$FyLQaUtr0b/nI6or1m1mpue3ZlHo3ih37JuP5l3IyKG.M92f9NB3S','operations');
SQL
