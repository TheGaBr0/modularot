# Resoconto — Verifica e riprogettazione dell'oblivious sampling (sntrup761, GGH, GGH-HNF)

*Sessione del 2026-08-14 (prosecuzione del lavoro MODULAROT). Autore: Claude (Fable 5), su richiesta di Gabriele Bottani.*

## Contesto

MODULAROT è un OT 1-su-n modulare su KEM intercambiabili (semi-honest). La receiver
privacy dipende dall'indistinguibilità tra chiave pubblica reale e chiave *oblivious*
(ben formata, senza segreto per nessuno); la sender privacy dal fatto che il sampler
non esegue mai KeyGen. Il sampling oblivious è necessariamente KEM-specifico (GKMRV,
FOCS 2000) e vive in `modularot/oblivious_sampling.py`.

Questa sessione ha coperto tre attività: (1) verifica matematica del sampler
sntrup761, (2) verifica del sampler GGH classico contro la libreria `GGH_crypto`
v1.0.5, (3) analisi di fattibilità e poi **implementazione completa** della variante
GGH-HNF con base piantata, in sostituzione del ramo GGH classico.

---

## 1. sntrup761 — sampler verificato SOUND

Verifica di `_ntruprime_encode` / `_make_ntruprime_sampler` contro la spec NTRU Prime
(Bernstein et al.) e contro liboqs (script: `scratchpad/verify_sntrup.py`,
13/13 PASS):

- **Encode = spec**: identico byte-per-byte all'Encode mixed-radix di riferimento su
  vettori casuali e casi limite (tutti 0, tutti q−1). L'unica differenza testuale
  (`R[i] + R[i+1]*M[i]` vs `R[i] + M[i]*R[i+1]`) è commutatività.
- **Serializzazione = liboqs**: su 30 chiavi reali, `Decode(pk)` dà 761 coefficienti
  in [0, 4591) e `Encode(Decode(pk)) == pk`; lunghezza costante 1158 B.
- **Distribuzione esatta**: Encode ristretto a [0,q)^761 è iniettivo a lunghezza
  fissa (`Decode∘Encode = id` su 200 vettori) ⇒ campionare coefficienti uniformi e
  codificare produce *esattamente* il pushforward dell'uniforme su R/q — l'oggetto
  che l'assunzione decisionale NTRU Prime dichiara indistinguibile da h = g/(3f).
  Unica discrepanza di supporto: h = 0 (mai reale, R/q è un campo), probabilità
  q^(−p) ≈ 2^(−9258), trascurabile.
- **Operativo**: encaps liboqs accetta le pk oblivious (15/15); χ² marginali:
  reali 8.0, oblivious 12.9 (df=15, soglia 99.9% = 37.7).
- Corretta anche l'esclusione di `ntrulpr*` (encoding Rounded, moduli per limb
  diversi → riusare questo Encode darebbe chiavi distinguibili).

---

## 2. GGH classico (pk = B = U·R) — sampler UNSOUND, receiver privacy rotta

Il vecchio `sample_oblivious_ggh` (matrice uniforme in [−M, M] con M = max|B|)
è stato verificato contro la vera keygen di `GGH_crypto` v1.0.5
(script: `scratchpad/verify_ggh.py`, dim 200, 5 coppie reale/oblivious).

Keygen reale: R = k·I + Uniform[−4,3] con k = 4·⌈√n+1⌉ (= 64 a n=200),
U unimodulare (2 passate di mixing pesato), B = U·R. **Quattro distinguisher
poly-time con separazione perfetta su singola chiave:**

| Statistica | Chiave reale | Chiave oblivious |
|---|---|---|
| log₂\|det B\| | ≈ 1199–1200 (= n·log₂k, rigido: det B = ±det R) | ≈ 13.900–14.900 |
| media \|entry\| | ≈ M/100 | ≈ M/2 |
| frac(\|entry\| > M/2) | 0,07 %–0,3 % | ≈ 50 % |
| norma media di riga | ~30× più piccola | — |

**Causa strutturale, non riparabile con un patch:** GGH non possiede un'assunzione
decisionale di pseudocasualità della pk. La distribuzione della pk è *definita dal
trapdoor* (B = U·R con R segreta): i suoi invarianti efficienti (det, profilo delle
norme, marginali) sono pubblicamente calcolabili e lontani da qualunque distribuzione
campionabile alla cieca. Il docstring originale ("under the GGH hardness assumption
B looks pseudorandom") era matematicamente falso: l'assunzione GGH è la durezza di
CVP in L(B) *dato* B, non la pseudocasualità della matrice.

Nota collaterale: la keygen classica con `nguyen_fix` richiede dim ≈ 200 per
ottenere σ > 2 (a dim 60 e 100 il loop di 100 tentativi fallisce).

### Chiarimento concettuale (domanda chiave della sessione)

Il reticolo *piantato* non è mai stato il problema — serve per decifrare. I canali
di leak sono due:
1. **invarianti di reticolo** (det): il sampler classico li sbagliava;
2. **artefatti di base** (la forma di U·R come matrice): inimitabili senza trapdoor,
   perché produrre una base "corta e mescolata" di un reticolo richiede conoscerne
   una base corta.

Il formato classico pubblica una *base* → canale 2 fatale e irreparabile. Il formato
HNF pubblica una *forma canonica del reticolo* → canale 2 sparisce, canale 1 si
matcha esattamente (v. sotto). Quel che resta è distinguere reticolo piantato da
reticolo casuale con stessi invarianti = trovare la base corta nascosta
(uSVP/GapSVP) — un'assunzione decisionale, stessa *forma* di quelle di LWE/NTRU.

---

## 3. GGH-HNF — analisi di fattibilità (script: `scratchpad/verify_ggh_hnf.py`)

Lettura di `GGH_crypto/GGH_HNF/GGH_HNF.py` + esperimenti (n = 40, 30 chiavi):

- **flint `.hnf()` è row-HNF upper-triangular** (diag > 0, entries sopra la
  diagonale ridotte in [0, d_i)). La `reduce_mod_B` della libreria assume invece
  lower-triangular: il ct resta congruente a r mod L (decifrabile) ma **non è
  ridotto** nella regione fondamentale. → Bug della libreria, aggirato nel nuovo
  ggh_fo con una riduzione propria.
- **Struttura delle HNF reali** (keygen piantata): diagonale quasi tutta 1 con 1–3
  entries non banali verso il fondo; le colonne con d_i = 1 hanno off-diagonale
  identicamente zero (forzato dalla riduzione [0,1)). Tutto il contenuto della pk
  sta nelle colonne dense.
- **Residui delle colonne dense reali ~ uniformi**: χ² = 12.5 (reale) vs 16.5
  (sampler uniforme), df 15 — nessun invariante economico separa.
- **`GGH_private=False` è inutilizzabile come KEM**: base privata = LLL(matrice
  uniforme), ma LLL(H_pubblica) dà una base *altrettanto buona* (min-GS 55.6 vs
  60.1 misurato) → trapdoor pubblico, chiunque decifra entrambi i branch.
- **`GGH_private=True`** (R = k·I + E, E uniforme in [−n, n−1], k = n·⌈√n+1⌉):
  trapdoor reale; gap piantato λ₁/GH ≈ 1.4 → assunzione decisionale *più*
  plausibile del classico (gap 3), a scapito del margine di decodifica.
- **σ pubblicato**: la pk della libreria è (H, R_ρ) con ρ derivato dalla base
  privata (min norma Gram-Schmidt) → canale di leak; da eliminare a favore di una
  regola d'errore pubblica funzione di n.

**Sampler "discarded-draw"** (l'idea risolutiva): estrai un keygen indipendente
R″ dalla stessa legge (con le stesse regole di accettazione), tieni solo
diag(HNF(R″)), scarta il resto; riempi le celle ridotte con uniformi in [0, d_i).
det e cokernel della chiave oblivious seguono così *esattamente* la legge del
keygen (stessa legge, estrazione indipendente). Sender privacy anche in
semi-honest: R″ nel tape del receiver genera un *altro* reticolo — della chiave
pubblicata rivela solo det/cokernel, pubblici comunque. (La variante naïve
"genera R′, pubblica HNF(R′), dimentica R′" fallisce proprio qui.)

Assunzione residua: **planted-short-basis / uSVP-gap decisionale** — non
dimostrata, e a dimensioni educational plausibilmente attaccabile con BKZ; la
storia è asintotica, come tutto il ramo GGH.

---

## 4. Implementazione (le tre versioni nel progetto)

### `modularot/custom_kems/ggh_fo/ggh_fo.py` — riscritto su GGH-HNF

KEM FO su `GGHHNFCryptosystem(GGH_private=True)`:

- **pk = solo HNF serializzata** (4B n | diagonale length-prefixed | colonne dense
  a larghezza fissa W_i = bytelen(d_i −1)). Niente ρ: regola d'errore pubblica
  **σ_e(n) = n//2**; la keygen rigetta R a meno che
  2·σ_e·max_j Σ_i |R⁻¹[i,j]| < 1 (condizione L1 di **colonna** — quella esatta per
  Babai rounding, e·R⁻¹ è somma per colonne) ⇒ **zero decryption failure**.
  Misurato σ_max ≈ 0.7·n (n=40: ~33, n=60: ~46, n=100: ~72) → accettazione ~1.
- **Riduzione upper-triangular propria** (`_reduce_mod_hnf`, sweep ascendente:
  la riga i tocca solo colonne ≥ i, le coordinate già ridotte restano ridotte).
- **FO su PKE deterministica** (schema Micciancio: il messaggio È il vettore
  d'errore e ∈ {±σ_e}^n, cifratura = riduzione nella regione fondamentale):
  niente hash di conferma; re-encryption check + rejection implicita con
  reject_key. ct = solo coordinate con d_i > 1.
- sk = pk ‖ R (n²×8B int64 BE) ‖ reject_key (32B).
- `draw_lattice_diag(n)`: un'estrazione *accettata* della legge keygen (stesse
  rejection di `gen`, RNG crittografico), che restituisce solo la diagonale —
  il supporto del sampler.

### `modularot/oblivious_sampling.py`

`sample_oblivious_ggh` **rimosso**; al suo posto `sample_oblivious_ggh_hnf`
(discarded-draw via `ggh_fo.draw_lattice_diag` + riempimento uniforme con
`secrets`). Il commento di sezione documenta il rifiuto del formato classico
(il det è un distinguisher perfetto) e la riduzione all'assunzione
planted-short-basis.

### Integrazione

- `cli.py`: label `GGH_HNF_FO-<dim>`, docstring aggiornati (`--ggh-dim`,
  default 200).
- `README.md`: motivazione dell'inclusione della sola variante HNF.
- `modularot/__init__.py`: docstring aggiornato.

### `tests/test_ggh_versions.py` — le tre versioni a confronto

| Versione | Esito | Evidenza (run a dim 60/40) |
|---|---|---|
| V1 GGH classica (B = U·R) | **RIFIUTATA** | log₂\|det\| 308.4 (teoria 310.2) vs 1828 del miglior sampler; frac(>M/2) 0.006 vs 0.51 |
| V2 GGH-HNF, `GGH_private=False` | **RIFIUTATA** | min-GS attaccante LLL(H) 44.9 vs 49.9 privata → trapdoor pubblico |
| V3 GGH-HNF, `GGH_private=True` | **SOUND** | roundtrip 10/10; rejection implicita deterministica (ct manomesso/troncato); det e legge della diagonale coincidenti; χ² residui 15.0 vs 19.7 (< 37.7); OT 1-su-2 e 1-su-4 correct + sender-private |

Esito complessivo: **15/15 PASS**. (N.B.: le dimensioni di default nel file di
test sono parametri delle funzioni; i numeri sopra sono delle run a 60/40 di
questa sessione.)

### Misure

- dim 200: gen 2.6 s, sampler 2.5 s, decaps 2.5 s; **pk ≈ 58 KB, ct = 292 B**
  (prima: pk 640 KB, ct ~3.2 KB) — il profilo di banda invertito si estremizza
  (compressione di Micciancio sul ct).
- Rapporto KeyGen/sampler ≈ **1×** (il discarded-draw *è* un keygen senza
  conservazione del segreto): terzo regime rispetto a ML-KEM (~0.1×) e
  Frodo/NTRU (~20×) — punto utile per la tesi.
- Benchmark CLI smoke-test: riga `GGH_HNF_FO-40` OK ✓ SEC ✓ (ct per branch ~91 B).

---

## 5. Caveat onesti (per la tesi)

1. L'assunzione planted-short-basis è **non dimostrata** e a dimensioni educational
   concretamente attaccabile (BKZ recupera basi corte con gap 1.4 a n ~ centinaia);
   tutto il ramo GGH resta "educational", coerentemente col suo status dichiarato.
2. Anche la sender privacy concreta è limitata dalle dimensioni: l'errore ±σ_e è
   piccolo rispetto a det^(1/n) ≈ n^1.5, quindi a dimensioni basse LLL/Babai può
   decodificare il branch oblivious. Stessa classe di caveat.
3. La keygen della libreria usa `random` (Mersenne Twister), non un RNG
   crittografico; il sampler usa `secrets`. Le *leggi* coincidono (è ciò che conta
   per l'indistinguibilità), ma per un KEM reale la keygen andrebbe portata su
   RNG crittografico.
4. Il bug `reduce_mod_B` (assume lower-triangular) resta nella libreria
   `GGH_crypto`; il nuovo ggh_fo non lo usa. Possibile fix upstream.

## 6. Possibili prossimi passi

- Rilanciare il benchmark completo (`modularot-bench --ggh-dim …`) per rigenerare
  i CSV della tesi con la riga GGH_HNF_FO.
- Valutare il fix upstream di `reduce_mod_B` in GGH_crypto (orientamento HNF).
- Angolo possibilmente nuovo per la tesi (non committato): OT robust combiner
  (HKNRR05) su famiglie lattice eterogenee.

## File toccati / creati in questa sessione

- `modularot/custom_kems/ggh_fo/ggh_fo.py` — riscritto (GGH-HNF FO)
- `modularot/oblivious_sampling.py` — sampler GGH sostituito
- `modularot/cli.py`, `modularot/__init__.py`, `README.md` — aggiornati
- `tests/test_ggh_versions.py` — nuovo (tre versioni)
- `RESOCONTO_GGH.md` — questo file
- Script di verifica (scratchpad di sessione, riusabili): `verify_sntrup.py`,
  `verify_ggh.py`, `verify_ggh_hnf.py`
