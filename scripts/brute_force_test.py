import requests
import time

URL = "http://127.0.0.1:5000/api/auth/login"
USERNAME = "testuser"

# Une petite liste de mots de passe à essayer - jamais le vrai, pour observer un vrai brute-force
PASSWORDS_TO_TRY = [
    "123456", "password", "azerty123", "Motdepasse1",
    "qwerty123", "Password1", "Test1234", "MotDePasse000",
    "admin123", "letmein1", "Bonjour123", "Welcome1",
    "testuser1", "MotDePasse999", "root1234",
]

def run_attack():
    print(f"Démarrage de l'attaque sur {URL}\n")

    for i, password in enumerate(PASSWORDS_TO_TRY, start=1):
        payload = {"username": USERNAME, "password": password}

        response = requests.post(URL, json=payload)

        print(f"Tentative {i:2d} | mot de passe testé: {password:20s} | "
              f"statut: {response.status_code}")

        if response.status_code == 429:
            print("\n>>> Blocage détecté (429 Too Many Requests) <<<")
            print(f">>> Réponse du serveur: {response.json()} <<<")
            break

        time.sleep(0.2)  # petite pause pour ne pas saturer le terminal de logs

    print("\nAttaque terminée.")

if __name__ == "__main__":
    run_attack()