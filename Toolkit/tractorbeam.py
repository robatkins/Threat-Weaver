
import mysql.connector

#TRACTORBEAM
#SQL SHA-256 Hash Uploader


# Database connection parameters
db_config = {
    'host': '',
    'user': '',
    'password': '',
    'database': '',
    'port': 1111
}

# Create a connection to the database
conn = mysql.connector.connect(**db_config)

# Create a cursor object to interact with the database
cursor = conn.cursor()

# Table creation SQL (modify as needed)
table_creation_sql = """
CREATE TABLE IF NOT EXISTS `Malware_Hashes` (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sha256_hash VARCHAR(64),
    md5_hash VARCHAR(32),
    file_name VARCHAR(255),
	threat_actor VARCHAR(255),
    malware_type VARCHAR(50),
    detection_date DATE
);
"""

# Execute the table creation SQL
cursor.execute(table_creation_sql)

# Commit the changes
conn.commit()

# Read SHA256 hashes from the file and insert into the table
file_path = 'malware_hashes.txt'

with open(file_path, 'r') as file:
    for line in file:
        sha256_hash = line.strip()

        # Insert into the table (assuming the md5_hash and other fields are NULL for now)
        insert_sql = "INSERT INTO Malware_Hashes (sha256_hash, md5_hash, file_name, threat_actor, malware_type, detection_date) VALUES (%s, NULL, NULL, NULL, NULL, NULL)"
        cursor.execute(insert_sql, (sha256_hash,))

# Commit the changes
conn.commit()

# Close the cursor and connection
cursor.close()
conn.close()

print(f"SHA256 hashes from {file_path} inserted into the Malware_Hashes table.")
