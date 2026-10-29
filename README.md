# SBOM Agent

Agente per generare uno **SBOM** (Software Bill of Materials) di un progetto,
in formato **CycloneDX 1.6** o **SPDX 2.3** (JSON).

Contiene due pezzi:

| File | Cosa fa |
|---|---|
| `.claude/agents/sbom.md` | Subagent di Claude Code: trova i manifest, genera lo SBOM, lo verifica e ti dà un report con i punti di attenzione |
| `sbom_agent/generate_sbom.py` | Generatore Python **senza dipendenze** (solo Python ≥ 3.11), usabile anche da solo o in CI |

## Usare l'agente (Claude Code)

Apri Claude Code in questo repository (o copia `.claude/agents/sbom.md` e la
cartella `sbom_agent/` nel tuo progetto) e chiedi, ad esempio:

> Fammi lo SBOM di questo progetto in formato SPDX

Claude userà l'agente `sbom`. Se sul sistema c'è `syft` o `cdxgen` li usa
(più completi), altrimenti usa lo script incluso.

## Usare lo script da solo

```bash
# CycloneDX su file + riepilogo
python3 sbom_agent/generate_sbom.py /percorso/progetto -o sbom.cdx.json --summary

# SPDX, senza dipendenze di sviluppo
python3 sbom_agent/generate_sbom.py . -f spdx --no-dev -o sbom.spdx.json
```

Opzioni: `--name`, `--version` (nome/versione del progetto), `--no-dev`,
`--summary` (riepilogo JSON su stderr: totali, componenti senza versione, errori).

## Ecosistemi supportati

| Linguaggio | File letti |
|---|---|
| Python | `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock` |
| Node.js | `package-lock.json` (v1–v3), `package.json` (se manca il lock) |
| Go | `go.mod` |
| Rust | `Cargo.lock` |
| Java | `pom.xml` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |

Ogni componente ha il suo **purl** (Package URL), utile per la scansione
vulnerabilità, es. `grype sbom:sbom.cdx.json` o `trivy sbom sbom.cdx.json`.

## Limiti

Lo script legge i file dichiarati, non analizza i binari o le immagini
container: per quello usa `syft`. Le dipendenze senza versione bloccata
(es. `flask>=3.0`) compaiono senza versione: meglio avere un lockfile.

## Test

```bash
python3 -m unittest discover -s tests -t .
```
