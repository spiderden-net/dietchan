# Beschreibung
Dietchan ist eine in C geschriebene Imageboard-Software.

Features:

- klein, schnell
- kein JS
- kein Caching, alles wird on-the-fly generiert
- kein Bloat™
- 9000 Zeilen reines C
- single-threaded, asynchron
- altbackenes Design
- Web 1.0

Beispiel-Installation:
https://dietchan.org/

## Wichtiger Hinweis

Das Datenbankformat könnte sich in Zukunft noch ändern, daher ist die Software momentan nicht für den Produktivbetrieb geeignet.

## Build-Abhängigkeiten

### Notwendig:

- Linux / BSD
- GCC
- CMake
- git

## Laufzeit-Abhängigkeiten

### Notwendig:

- Linux / BSD
- file
- ImageMagick / GraphicsMagick
- ffmpeg

### Empfohlen:

- pngquant

## Kompilieren

    cmake -DCMAKE_BUILD_TYPE=Release . && make

So ein Fach ist das!
