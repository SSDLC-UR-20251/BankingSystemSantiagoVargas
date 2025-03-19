from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys


import re
import time

driver = webdriver.Chrome()
driver.get("http://127.0.0.1:5000/api/login?error=Tu+sesi%C3%B3n+ha+expirado.+Inicia+sesi%C3%B3n+nuevamente.")

driver.find_element(By.ID, "email").send_keys("davids.vargas@urosario.edu.co")
driver.find_element(By.ID, "password").send_keys("S@ntiago12345")
driver.find_element(By.ID, "login").click()

time.sleep(2)

saldo_texto = driver.find_element(By.ID, "saldo_usuario").text
saldo_inicial = float(saldo_texto.split(":")[-1].strip())

driver.find_element(By.ID,"deposit_button").click()

#print(f"Saldo inicial: {saldo_inicial}")

time.sleep(2)

driver.find_element(By.ID, "balance").send_keys("100")
driver.find_element(By.ID, "deposit_button1").click()

time.sleep(2)

saldo_texto_final = driver.find_element(By.ID, "saldo_usuario").text
saldo_final = float(saldo_texto_final.split(":")[-1].strip())

#print(f"Saldo final: {saldo_final}")

assert saldo_final == saldo_inicial + 100,f"Error: saldo esperado {saldo_inicial + 100}, pero se obtuvo {saldo_final}"

time.sleep(2)

saldo_texto = driver.find_element(By.ID, "saldo_usuario").text
saldo_inicial = float(saldo_texto.split(":")[-1].strip())

driver.find_element(By.ID,"withdraw_button").click()

#print(f"Saldo inicial: {saldo_inicial}")

time.sleep(2)

driver.find_element(By.ID, "balance").send_keys("100")
driver.find_element(By.ID, "password").send_keys("S@ntiago12345")
driver.find_element(By.ID, "withdraw_button1").click()

time.sleep(2)

saldo_texto_final = driver.find_element(By.ID, "saldo_usuario").text
saldo_final = float(saldo_texto_final.split(":")[-1].strip())

#print(f"Saldo final: {saldo_final}")

assert saldo_final == saldo_inicial - 100,f"Error: saldo esperado {saldo_inicial - 100}, pero se obtuvo {saldo_final}"

time.sleep(2)

driver.find_element(By.ID, "salir").click()

time.sleep(2)

driver.find_element(By.ID, "email").send_keys("davids.vargas@urosario.edu.co")
driver.find_element(By.ID, "password").send_keys("Santi")
driver.find_element(By.ID, "login").click()


intentos = 2;
texto_error = driver.find_element(By.ID, "error_login").text
assert texto_error == "Credenciales incorrectas. Tienes 2 intentos restantes.",f"Error: intentos esperados {intentos}, pero se obtuvo {texto_error}"

time.sleep(2)

driver.quit()