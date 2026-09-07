def map_to_list(list1, list2):

    # Initialize a list with zeros
    caste_list = [0] * len(list2)

    # Map the input caste category to the list
    try:
        index = list1.index(list1)
        caste_list[index] = 1
    except ValueError:
        print("Invalid caste category.")

    return caste_list
	
import tenseal as ts
import numpy as np

def context():
    context = ts.context(ts.SCHEME_TYPE.CKKS, 8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.global_scale = pow(2, 40)
    context.generate_galois_keys()
    return context

context = context()

"""

Possible Categories
Gender: {Male, Female, Transgender, Other}
Caste Category: {Scheduled Tribe (ST), Scheduled Caste (SC), Other Backward Class (OBC), General (Unreserved), Economically Weaker Section (EWS), Other}
Religious Belief: {Hindu, Muslim, Christian, Sikh, Jain, Buddhist, Parsi, Other}
Sexual Orientation: {Heterosexual, Homosexual, Lesbian, Bisexual, Asexual, Other}
Racial or Ethnic: {Kashmiri, Northeast Indian, North Indian, South Indian, East Indian, West Indian, Gujarati, Punjabi, Bengali, Other}
"""

gender = ts.plain_tensor([0, 1, 0, 0], [4, 1])  # [0, 1, 1, 0] --> [male, female, transgender, other]
casteCat = ts.plain_tensor([1, 1, 0, 0, 0, 0], [6, 1]) # [1, 1, 0, 0, 0, 0] --> {Scheduled Tribe (ST), Scheduled Caste (SC), Other Backward Class (OBC), General (Unreserved), Economically Weaker Section (EWS), Other}
relBel = ts.plain_tensor([0, 0, 0, 0, 0, 0, 0, 0], [8, 1])
sexOrien = ts.plain_tensor([0, 0, 0, 0, 0, 0], [6, 1])
racial = ts.plain_tensor([1, 1, 0, 0, 0, 0, 0, 0, 0, 0], [10, 1])

# Encrypt the data
encrypted_gender = ts.ckks_tensor(context, gender)
encrypted_casteCat = ts.ckks_tensor(context, casteCat)
encrypted_relBel = ts.ckks_tensor(context, relBel)
encrypted_sexOrien = ts.ckks_tensor(context, sexOrien)
encrypted_racial = ts.ckks_tensor(context, racial)

categories = ["Scheduled Tribe", "Scheduled Caste", "Other Backward Class", "General", "Economically Weaker Section", "Other"]
gender = ["Male", "Female", "Transgender", "Other"]
ReligiousBelief= ["Hindu", "Muslim", "Christian", "Sikh", "Jain", "Buddhist", "Parsi", "Other"]
SexualOrientation= ["Heterosexual", "Homosexual", "Lesbian", "Bisexual", "Asexual", "Other"]
Racial= ["North Indian", "South Indian", "East Indian", "West Indian", "Kashmiri", "Northeast Indian", "Gujarati", "Punjabi", "Bengali", "Other"]

print("Persional Identifiable Information")

input_name = input("Enter Name: ")
input_address = input("Enter address: ")
input_dateofbirth = input("Enter date of birth ")
input_phonenumber = input("Enter phonenumber: ")

print("\n\nSenstitive Information")
input_caste = input("Enter caste category (Scheduled Tribe/Scheduled Caste/Other Backward Class/General/Economically Weaker Section/Other): ")
input_gender = input("Enter gender (Male/Female/Transgender/Other): ")
input_relBel = input("Enter religion believe (Hindu/Muslim/Christian/Sikh/Jain/Buddhist/Parsi/Other): ")
input_sexOrien = input("Enter sexual orientation (Heterosexual/Homosexual/Lesbian/Bisexual/Asexual/Other): ")
input_racial = input("Enter ethinicity (North Indian/South Indian/East Indian/West Indian/Kashmiri/Northeast Indian/Gujarati/Punjabi/Bengali/Other): ")

print("\n\nfinancial Information")
input_salary = input("Enter salary: ")
input_loanamount = input("Enter loan amount: ")
input_typeOfloan = input("Enter type of loan ")



output_caste = map_to_list(input_caste, categories)
output_gender = map_to_list(input_gender, gender)
output_relBel = map_to_list(input_relBel, ReligiousBelief)
output_sexOrien = map_to_list(input_sexOrien, SexualOrientation)
output_racial = map_to_list(input_racial, Racial)

#print(f"Output list: {output_caste}")
#print(f"Output list: {output_gender}")

encrypted_input_gender = ts.ckks_tensor(context, ts.plain_tensor(output_gender, [len(output_gender), 1]))
encrypted_input_casteCat = ts.ckks_tensor(context, ts.plain_tensor(output_caste, [len(output_caste), 1]))
encrypted_input_relBel = ts.ckks_tensor(context, ts.plain_tensor(output_relBel, [len(output_relBel), 1]))
encrypted_input_sexOrien = ts.ckks_tensor(context, ts.plain_tensor(output_sexOrien, [len(output_sexOrien), 1]))
encrypted_input_racial = ts.ckks_tensor(context, ts.plain_tensor(output_racial, [len(output_racial), 1]))

print("Encrypted sensitive information\n")
print("encrypted_gender: ", encrypted_input_gender)
print("encrypted Caste : ", encrypted_input_casteCat)
print("encrypted_religous belief: ", encrypted_input_relBel)
print("encrypted sexual orientation : ", encrypted_input_sexOrien)
print("encrypted_ethinicity: ", encrypted_input_racial)

