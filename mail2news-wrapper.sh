#!/bin/bash

# Log più dettagliato
exec > >(tee -a /tmp/mail2news-wrapper.log) 2>&1
echo "$(date): Wrapper script avviato"

# Crea una directory temporanea per l'input e output
TEMP_DIR=$(mktemp -d)
RAW_EMAIL="$TEMP_DIR/raw_email.txt"
CLEANED_EMAIL="$TEMP_DIR/clean_email.txt"

# Leggi l'email da stdin e salvala
cat > "$RAW_EMAIL"
echo "$(date): Email salvata in $RAW_EMAIL"

# Pre-elaborazione per creare un articolo valido
echo "$(date): Pre-elaborazione dell'email"

# Estrai le intestazioni necessarie dalla mail originale
grep -i "^From:" "$RAW_EMAIL" > "$CLEANED_EMAIL" || echo "From: anonymous@mail2news.tcpreset.net" > "$CLEANED_EMAIL"
grep -i "^Subject:" "$RAW_EMAIL" >> "$CLEANED_EMAIL" || echo "Subject: (No Subject)" >> "$CLEANED_EMAIL"
grep -i "^To:" "$RAW_EMAIL" | grep "mail2news" > /dev/null && \
    grep -i "^To:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^Newsgroups:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^Message-ID:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
# Preserva gli header per il threading
grep -i "^References:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^In-Reply-To:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^X-Ed25519-Sig:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^X-Ed25519-Pub:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^X-No-Archive:" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
grep -i "^X-Hashcash" "$RAW_EMAIL" >> "$CLEANED_EMAIL"
echo "" >> "$CLEANED_EMAIL"  # Linea vuota tra header e body

# Estrai il corpo della mail (tutto ciò che segue la prima riga vuota)
sed -n '/^$/,$p' "$RAW_EMAIL" | tail -n +2 >> "$CLEANED_EMAIL"

# Log dell'articolo preparato
echo "== ARTICOLO PREPARATO PER NNTP =="
cat "$CLEANED_EMAIL"
echo "== FINE ARTICOLO =="

# Esegui mail2news con l'email prepulita
echo "$(date): Esecuzione mail2news"
sudo -u mail2news /usr/local/bin/mail2news < "$CLEANED_EMAIL" 2>&1
RESULT=$?
echo "$(date): mail2news terminato con codice $RESULT"

# Pulisci
rm -f "$RAW_EMAIL" "$CLEANED_EMAIL"
rmdir "$TEMP_DIR"
