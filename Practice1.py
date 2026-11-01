domains = ["bkash.com","darz.com.bd","grameenphone.com"]

for domain in domains:
    name, tld = domain.split(".",1)
    print(domain, "->", "Name:", name, ", TLD:", tld)