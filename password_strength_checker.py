"""
DecodeLabs - Cyber Security Industrial Training Kit
Project 1: Password Strength Checker

Goal: Check whether a password is Weak, Medium, or Strong
based on length, character variety, and basic pattern checks.
"""

import re

# A small sample list of extremely common leaked passwords.
# In a real tool this would be loaded from a much larger breach-list file.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "password1", "111111", "letmein", "iloveyou", "admin"
}


def check_password_strength(password: str) -> dict:
    """
    Analyze a password and return a dict with:
    - score (0-5)
    - strength label (Weak / Medium / Strong)
    - list of feedback messages
    """
    feedback = []
    score = 0

    # 1. Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short — use at least 8 characters (12+ is better).")

    # 2. Character variety checks
    has_lower = any(char.islower() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_digit = any(char.isdigit() for char in password)
    has_symbol = any(not char.isalnum() for char in password)

    if has_lower:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if has_upper:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if has_digit:
        score += 1
    else:
        feedback.append("Add at least one number.")

    if has_symbol:
        score += 1
    else:
        feedback.append("Add at least one symbol (e.g. ! @ # $ %).")

    # 3. Common / leaked password check (bonus from the brief)
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        feedback.append("This password appears in common leaked password lists — avoid it entirely.")

    # 4. Repeated / sequential pattern check (bonus)
    if re.search(r"(.)\1{2,}", password):  # e.g. "aaa", "111"
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    # Clamp score
    score = max(0, min(score, 6))

    # 5. Classify strength
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    if not feedback:
        feedback.append("Great job! This password meets all the checks.")

    return {"score": score, "strength": strength, "feedback": feedback}


def print_report(password: str) -> None:
    result = check_password_strength(password)
    bar = {"Weak": "🔴", "Medium": "🟠", "Strong": "🟢"}[result["strength"]]

    print("\n--- Password Strength Report ---")
    print(f"Password:  {'*' * len(password)}")
    print(f"Strength:  {bar} {result['strength']}  (score: {result['score']}/6)")
    print("Feedback:")
    for tip in result["feedback"]:
        print(f"  - {tip}")
    print("---------------------------------\n")


def main():
    print("=== DecodeLabs Password Strength Checker ===")
    while True:
        pwd = input("Enter a password to check (or 'q' to quit): ")
        if pwd.lower() == "q":
            print("Goodbye!")
            break
        print_report(pwd)


if __name__ == "__main__":
    main()