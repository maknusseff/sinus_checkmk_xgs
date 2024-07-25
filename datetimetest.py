import datetime

lic_exp_t = "Dec 21 2099"

now = datetime.datetime.now()
lic_exp_d = datetime.datetime.strptime(lic_exp_t, "%b %d %Y")

lic_delta = lic_exp_d - now
lic_delta = int(str(lic_delta).split(" ", 1)[0])

print(str(lic_delta) + " days to go")