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

fmt:
  cd common && clang-format -i *.c *.h
  cd pam-module && clang-format -i *.c
  cd linux-daemon && cargo fmt
 
gen-compile-commands:
  cd common && make clean && bear -- make all
  cd pam-module && make clean && bear -- make all

lint: gen-compile-commands
  cd common && clang-tidy *.c
  cd pam-module && clang-tidy *.c
  cd linux-daemon && cargo clippy
  cd wearos-app && ./gradlew lint

