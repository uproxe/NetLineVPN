#!/usr/bin/env bash
# Последние стабильные Android Gradle Plugin 9.x и Gradle 9.x. Печатает строки ключ=значение.
set -euo pipefail
AGP="$(curl -fsSL https://dl.google.com/dl/android/maven2/com/android/tools/build/gradle/maven-metadata.xml \
  | grep -oP '(?<=<version>)9\.[0-9]+\.[0-9]+(?=</version>)' | sort -V | tail -1)"
GRADLE="$(curl -fsSL https://services.gradle.org/versions/all | python3 -c "
import json, sys
v = [x['version'] for x in json.load(sys.stdin)
     if x['version'].startswith('9.') and not (x['snapshot'] or x['nightly'] or x['releaseNightly'] or x['broken'] or x['rcFor'] or x['milestoneFor'])]
print(sorted(v, key=lambda s: [int(p) for p in s.split('.')])[-1])")"
echo "agp=$AGP"
echo "gradle=$GRADLE"
