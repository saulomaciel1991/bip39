#!/usr/bin/env python3
import os
import sys
import hmac
import hashlib
import argparse
import unicodedata
from datetime import datetime

# ==============================================================================
# SECP256k1 Curve Parameters & Arithmetic (Zero dependências externas)
# ==============================================================================
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
# Ordem real da curva SECP256k1 (n)
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1) * pow(2 * y1, _P - 2, _P) % _P
    else:
        m = (y2 - y1) * pow(x2 - x1, _P - 2, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)

def point_mul(k):
    res = None
    addend = (_Gx, _Gy)
    while k:
        if k & 1:
            res = point_add(res, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return res

def pubkey_compressed(k_bytes):
    k_int = int.from_bytes(k_bytes, "big")
    x, y = point_mul(k_int)
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


# ==============================================================================
# Bech32 Encoding (BIP173 / SegWit Native v0)
# ==============================================================================
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for val in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ val
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def segwit_addr(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    checksum = bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in data + checksum])


# ==============================================================================
# BIP32 Key Derivation
# ==============================================================================
def ckd_priv(parent_key, parent_chain, index):
    if index >= 0x80000000:
        data = b"\x00" + parent_key + index.to_bytes(4, "big")
    else:
        pub = pubkey_compressed(parent_key)
        data = pub + index.to_bytes(4, "big")
    I = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_int = (int.from_bytes(I[:32], "big") + int.from_bytes(parent_key, "big")) % _N
    return child_int.to_bytes(32, "big"), I[32:]

def derive_bip84_address(parent_key, parent_chain, address_index):
    k_child, _ = ckd_priv(parent_key, parent_chain, address_index)
    pub_child = pubkey_compressed(k_child)
    sha = hashlib.sha256(pub_child).digest()
    ripemd = hashlib.new("ripemd160", sha).digest()
    return segwit_addr("bc", 0, ripemd)


# ==============================================================================
# Helper Functions: Arquivos e Configurações
# ==============================================================================
def load_env(env_path="bip39.env"):
    if not os.path.exists(env_path):
        raise FileNotFoundError(f"Arquivo de ambiente '{env_path}' não foi encontrado.")
    config = {}
    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip().strip("'\"")
    return config

def load_targets(target_path):
    if not os.path.exists(target_path):
        raise FileNotFoundError(f"Arquivo target '{target_path}' não foi encontrado.")
    targets = {}
    with open(target_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                targets[key] = val
    if "seed" not in targets:
        raise ValueError("O arquivo target.txt deve conter a linha 'seed: <mnemônico>'.")
    if "address0" not in targets:
        raise ValueError("O arquivo target.txt deve conter pelo menos 'address0: <bc1q...>'.")
    return targets

def load_passphrases(passphrase_path):
    if not os.path.exists(passphrase_path):
        raise FileNotFoundError(f"Arquivo de passphrases '{passphrase_path}' não foi encontrado.")
    passphrases = []
    with open(passphrase_path, "r", encoding="utf-8") as f:
        for line in f:
            clean_line = line.rstrip("\r\n")
            if clean_line:
                passphrases.append(clean_line)
    return passphrases


# ==============================================================================
# Main Verification Flow (Suporte a modo Normal e --debug)
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="Recuperador e validador de passphrases BIP39/BIP84 offline."
    )
    parser.add_argument(
        "--debug", "-d",
        action="store_true",
        help="Ativa modo detalhado (exibe seed hex, normalização e status passo a passo)."
    )
    args = parser.parse_args()
    debug_mode = args.debug

    print("=" * 70)
    print("  BIP39 Passphrase Recovery & Validator (BIP84 / Native SegWit)")
    if debug_mode:
        print("  [MODO DEBUG ATIVADO]")
    print("=" * 70)

    try:
        config = load_env("bip39.env")
    except Exception as e:
        print(f"[ERRO] Falha ao carregar bip39.env: {e}")
        sys.exit(1)

    target_path = config.get("TARGET_PATH", "./target.txt")
    passphrase_path = config.get("PASSPHRASE_PATH", "./passphrases.csv")

    try:
        targets = load_targets(target_path)
    except Exception as e:
        print(f"[ERRO] Falha ao ler {target_path}: {e}")
        sys.exit(1)

    try:
        passphrases = load_passphrases(passphrase_path)
    except Exception as e:
        print(f"[ERRO] Falha ao ler {passphrase_path}: {e}")
        sys.exit(1)

    raw_mnemonic = targets["seed"]
    words = raw_mnemonic.split()
    cleaned_mnemonic = " ".join(words)
    norm_mnemonic = unicodedata.normalize("NFKD", cleaned_mnemonic)

    target_addr0 = targets.get("address0")
    target_addr9 = targets.get("address9")
    target_addr19 = targets.get("address19")

    if debug_mode:
        print("[DEBUG] Detalhes do Mnemônico (Seed Words):")
        print(f"  - Texto bruto no target.txt : {repr(raw_mnemonic)}")
        print(f"  - Texto normalizado (NFKD)  : {repr(norm_mnemonic)}")
        print(f"  - Quantidade de palavras    : {len(words)}")
        print(f"  - Teve espaços extras limpos: {'Sim' if raw_mnemonic != cleaned_mnemonic else 'Não'}\n")
        print("[DEBUG] Endereços Alvo Carregados:")
        print(f"  - Alvo index 0 : {target_addr0}")
        if target_addr9:
            print(f"  - Alvo index 9 : {target_addr9}")
        if target_addr19:
            print(f"  - Alvo index 19: {target_addr19}")
        print()
    else:
        print(f"[*] Mnemônico carregado: {len(words)} palavras")
        print(f"[*] Alvo index 0 : {target_addr0}")
        if target_addr9:
            print(f"[*] Alvo index 9 : {target_addr9}")
        if target_addr19:
            print(f"[*] Alvo index 19: {target_addr19}")

    print(f"[*] Total de palpites a testar: {len(passphrases)}")
    print("-" * 70)

    mnemonic_bytes = norm_mnemonic.encode("utf-8")
    match_found = False

    for idx, candidate in enumerate(passphrases, start=1):
        norm_passphrase = unicodedata.normalize("NFKD", candidate)
        salt = unicodedata.normalize("NFKD", "mnemonic" + norm_passphrase).encode("utf-8")

        # 1. PBKDF2 HMAC-SHA512 (2048 iterações)
        bip39_seed = hashlib.pbkdf2_hmac("sha512", mnemonic_bytes, salt, 2048)

        # 2. Master Key
        I = hmac.new(b"Bitcoin seed", bip39_seed, hashlib.sha512).digest()
        k, c = I[:32], I[32:]

        # 3. BIP84 Path: m/84'/0'/0'/0
        for path_index in [84 | 0x80000000, 0 | 0x80000000, 0 | 0x80000000, 0]:
            k, c = ckd_priv(k, c, path_index)

        # 4. Derivação do índice 0 (Early Exit)
        addr0 = derive_bip84_address(k, c, 0)

        if debug_mode:
            seed_hex = bip39_seed.hex()
            print(f"[{idx}/{len(passphrases)}] Testando passphrase: {repr(candidate)}")
            print(f"       -> BIP39 Seed (512-bit hex): {seed_hex[:16]}...{seed_hex[-16:]}")
            print(f"       -> Endereço derivado idx 0 : {addr0}")

        if addr0 != target_addr0:
            if debug_mode:
                print(f"       -> Status: ❌ DIFERENTE (esperado: {target_addr0})\n")
            else:
                # No modo rápido/simples, imprime apenas status sucinto por linha
                print(f"[{idx}/{len(passphrases)}] Incorreta: '{candidate}'")
            continue

        # Match no endereço 0!
        if debug_mode:
            print(f"       -> Status: ✅ MATCH NO ENDEREÇO 0!")
            print("\n    [+] Verificando confirmação nos endereços 9 e 19...")
        else:
            print(f"\n[!] MATCH NO ENDEREÇO 0 encontrado com: '{candidate}'")
            print("    Validando endereços adicionais para confirmação 100%...")

        all_ok = True
        if target_addr9:
            addr9 = derive_bip84_address(k, c, 9)
            if debug_mode:
                print(f"    - Endereço 9 : {addr9} ({'✅ IGUAL' if addr9 == target_addr9 else '❌ DIVERGENTE'})")
            if addr9 != target_addr9:
                all_ok = False

        if target_addr19:
            addr19 = derive_bip84_address(k, c, 19)
            if debug_mode:
                print(f"    - Endereço 19: {addr19} ({'✅ IGUAL' if addr19 == target_addr19 else '❌ DIVERGENTE'})")
            if addr19 != target_addr19:
                all_ok = False

        if not all_ok:
            print("    [!] Atenção: Algum endereço adicional não coincidiu, continuando busca...\n")
            continue

        # Confirmação total!
        seed_hex = bip39_seed.hex()
        match_found = True
        print("\n" + "=" * 70)
        print("  🎉 SUCESSO! PASSPHRASE ENCONTRADA E CONFIRMADA!")
        print("=" * 70)
        print(f"  Passphrase   : {candidate}")
        print(f"  BIP39 Seed   : {seed_hex}")
        print(f"  Endereço 0   : {addr0}")
        if target_addr9:
            print(f"  Endereço 9   : {target_addr9}")
        if target_addr19:
            print(f"  Endereço 19  : {target_addr19}")
        print("=" * 70)

        # Salva no recovered.txt
        with open("recovered.txt", "w", encoding="utf-8") as f_out:
            f_out.write(f"Recuperado em : {datetime.now().isoformat()}\n")
            f_out.write(f"Passphrase    : {candidate}\n")
            f_out.write(f"BIP39 Seed    : {seed_hex}\n")
            f_out.write(f"Address 0     : {addr0}\n")
            if target_addr9:
                f_out.write(f"Address 9     : {target_addr9}\n")
            if target_addr19:
                f_out.write(f"Address 19    : {target_addr19}\n")

        print("[+] Informações salvas com sucesso em 'recovered.txt'\n")
        break

    if not match_found:
        print("\n" + "-" * 70)
        print(f"[-] Finalizado: Nenhum dos {len(passphrases)} palpites gerou os endereços alvos.")
        print("-" * 70)

if __name__ == "__main__":
    main()
