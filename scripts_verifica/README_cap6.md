# Suite di verifica del Capitolo 6

Esegue i passi descritti nel Capitolo 6 della tesi
(*Verifica delle proprietà di sicurezza e degli attacchi al framework*) e ne
produce numeri + figure.

## Esecuzione

```bash
# tutto (≈ 2 min)
.venv/bin/python scripts_verifica/run_cap6.py
# rapido (meno chiavi)
.venv/bin/python scripts_verifica/run_cap6.py --quick
# singola sezione
.venv/bin/python scripts_verifica/cap6_1_campionatori.py
```

Output in `scripts_verifica/cap6_output/`: una `*.png` per sezione/famiglia,
i dati grezzi in `*.json`, la tabella LaTeX `tabella_6.1.tex`, e `index.html`
che raccoglie tutte le figure.

## File

| file | sezione tesi | cosa fa |
|---|---|---|
| `cap6_common.py` | — | φ per famiglia, KS a due campioni, χ² + soglia di Wilson-Hilferty, entropia di Shannon e min-entropia MCV (NIST SP 800-90B), catalogo dei campionatori |
| `cap6_1_campionatori.py` | 6.1 | i 4 passi (strutturale · KS · χ² · metriche descrittive) per ogni campionatore di Tabella `tab:phi-schemi` |
| `cap6_2_ggh.py` | 6.2 | esempio $n=5$ di Fig. 6.1 (riprodotto esattamente), separazione statistica di GGH classico su più dimensioni, GGH-HNF `GGH_private=False` → trapdoor pubblica |
| `cap6_3_mix_and_match.py` | 6.3 | riuso di `ct`/`ss`/`k` fuori dalla tripla `(sid, i, pk_i)`: ogni tentativo respinto dal legame HKDF + AEAD |
| `cap6_4_avversariale.py` | 6.4 | ricevente curioso (`receiver_cannot_read_other` + variante con `sk_b` propria) e mittente curioso (riduzione a 6.1) |
| `run_cap6.py` | — | esegue tutto e assembla `index.html` |
| `verify_*.py` | — | script esplorativi storici (precedono questa suite) |

## Esito sintetico

- **6.1** — i 7 campionatori superano tutti i passi: verifica strutturale
  esatta, KS non rigetta $H_0$ (mediana su 9 sotto-campioni), χ² coerente fra
  chiavi reali e oblivious.
- **6.2** — l'esempio $n=5$ coincide con la tesi ($|\det B| = 70$ vs $9614$,
  $0/25$ vs $13/25$ entrate grandi); det e marginali delle entrate separano
  reale da campionata a ogni dimensione; GGH-HNF `GGH_private=False` ha la
  trapdoor pubblica.
- **6.3** — tutti i riusi fuori dalla tripla sono respinti; l'esecuzione
  onesta apre $m_b$.
- **6.4** — mittente curioso: nessun vantaggio (si riduce a 6.1). Ricevente
  curioso: ogni messaggio non scelto resta nascosto per tutte le famiglie.

  `receiver_cannot_read_other` (in `ot_protocol.py`) è stato rafforzato: per
  ogni `i != b` prova la decapsulazione di `ct_i` con una chiave fabbricata e
  con la vera `sk_b` del ricevente, su un'istanza di KEM fresca e su quella che
  il ricevente detiene. Questo controllo ha fatto emergere un difetto in
  `NTRU_FO._hash_to_randomness`, che leggeva SHAKE con `shake.digest(1)` in un
  ciclo — `digest(n)` restituisce sempre il *prefisso* dell'output, quindi ogni
  iterazione rileggeva il primo byte e `r` collassava a un polinomio costante
  ($0$, $\sum x^i$ o il suo opposto). Con `r = 0` il ciphertext coincideva col
  messaggio e il controllo di ri-cifratura FO smetteva di legare la chiave.
  Corretto leggendo l'XOF come stream (`ntru_fo.py`, `_hash_to_randomness`);
  dopo la correzione `r` è pseudocasuale ternario e tutte le famiglie superano
  il test. Vedi `cap6_output/6.4_avversariale.json` → `diagnosi_ntru_fo`.
