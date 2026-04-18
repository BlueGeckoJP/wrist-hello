default:
  @just --list

build:
  cd common && make all
  cd pam-module && make all
  cd linux-daemon && cargo build
  cd wearos-app && ./gradlew assembleDebug

test: build
  cd pam-module && make test
  cd wearos-app && ./gradlew test

clean:
  cd common && make clean
  cd pam-module && make clean
  cd linux-daemon && cargo clean
  cd wearos-app && ./gradlew clean

