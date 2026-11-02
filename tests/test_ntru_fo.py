from modularot.custom_kems.ntru_fo.ntru_fo import NTRU_FO
from modularot.kem_adapter.adapter import KEMAdapter

impl = NTRU_FO(N=701, p=3, q=8192)

kem = KEMAdapter(
    gen=impl.generate_keys,
    encap=impl.encapsulate,
    decap=impl.decapsulate,
)

public_key, private_key = kem.Gen()

# Test 1: Normal operation
print("\n" + "=" * 80)
print("Test 1: Normal KEM operation")
print("=" * 80)

ss_alice, ct = kem.encaps(public_key)
print(f"✓ Encapsulation complete ({len(ct)} bytes)")
print(f"  Session key (Alice): {ss_alice.hex()[:32]}...")

ss_bob = kem.decaps(private_key, ct)
print(f"  Session key (Bob):   {ss_bob.hex()[:32]}...")
print(f"✓ Keys match: {ss_alice == ss_bob}")
