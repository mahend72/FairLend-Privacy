# Check Gender and Caste (Eligiblity Check)

SoP_gender = encrypted_gender * encrypted_input_gender
SoP_gender = SoP_gender.sum(axis=0)
check_gender = round(SoP_gender.decrypt().tolist()[0])
if check_gender==1:
  print("True")
else:
  print("False")

SoP_casteCat = encrypted_casteCat * encrypted_input_casteCat
SoP_casteCat = SoP_casteCat.sum(axis=0)
check_casteCat = round(SoP_casteCat.decrypt().tolist()[0])
if check_casteCat==1:
  print("True")
else:
  print("False")

SoP_relBel = encrypted_relBel * encrypted_input_relBel
SoP_relBel = SoP_relBel.sum(axis=0)
check_relBel = round(SoP_relBel.decrypt().tolist()[0])

if check_relBel==1:
  print("True")
else:
  print("False")

SoP_sexOrien = encrypted_sexOrien * encrypted_input_sexOrien
SoP_sexOrien = SoP_sexOrien.sum(axis=0)
check_sexOrien = round(SoP_sexOrien.decrypt().tolist()[0])
if check_sexOrien==1:
  print("True")
else:
  print("False")

SoP_racial = encrypted_racial * encrypted_input_racial
SoP_racial = SoP_racial.sum(axis=0)
check_racial = round(SoP_racial.decrypt().tolist()[0])
if check_racial==1:
  print("True")
else:
  print("False")
