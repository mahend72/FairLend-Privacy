#Virtual identity
def generate_virtual_id(unique_id, expiration_date):
    # Concatenate the unique ID and expiration date
    data = f"{unique_id}{expiration_date}"

    # Calculate the SHA-256 hash of the concatenated data
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()

    # Extract a 6-digit substring from the hash
    virtual_id_str = sha256_hash[:6]

    return virtual_id_str
	
#Function: ID generation

import hashlib
import datetime

def generate_unique_id(PII, bio_info):
    # Concatenate PII fields and bio_info
    data = f"{PII['Name']}{PII['Address']}{PII['DateOfBirth']}{PII['PhoneNumber']}{bio_info}"

    # Calculate the SHA-256 hash of the concatenated data
    sha256_hash = hashlib.sha256(data.encode()).hexdigest()

    # Extract a 16-digit substring from the hash
    unique_id_str = sha256_hash[:15]

    # Convert the substring to an integer
    unique_id = int(unique_id_str, 16)  # Interpret as a hexadecimal number

    return unique_id
	
# Step 1: ID and VID Generation
unique_id = generate_unique_id(PII, bio_info)

print("Unique Identifier:", unique_id)

current_date = datetime.date.today()
expiration_date = current_date + datetime.timedelta(days=30)
virtual_id = generate_virtual_id(unique_id, expiration_date)


print("Virtual ID:", virtual_id)
	
	