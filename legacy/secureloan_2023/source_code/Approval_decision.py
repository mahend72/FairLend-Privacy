#Loan approval decision
# Check if the result is equal to 1

print("Encrypted sensitive information\n")
print("encrypted_gender: ", encrypted_input_gender)
print("encrypted Caste : ", encrypted_input_casteCat)
print("encrypted_religous belief: ", encrypted_input_relBel)
print("encrypted sexual orientation : ", encrypted_input_sexOrien)
print("encrypted_ethinicity: ", encrypted_input_racial)

if check_gender == 1 or check_casteCat == 0:
    print("\n The applicant is not eligible for any government beneficial scheme, so he qualifies for a higher interest rate. !!")
else:
    print("\nThe applicant is eligible for government beneficial scheme, so he qualifies for a low interest rate. !!")
	
