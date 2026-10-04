# jwt-lab

Экспериментальный CLI для выпуска и проверки JWT на Rust. Это продолжение исследований JWT/LWT: [JWT](https://github.com/localzet/JWT), [LWT](https://github.com/localzet/LWT), [localzet-jose](https://github.com/localzet/localzet-jose). Общий topic: `localzet-tokens`.

## Рабочая часть

CLI использует `jsonwebtoken` и разрешает **только HS256**. `verify` проверяет подпись, `exp` без дополнительного временного допуска и издателя `jwtgate`. `inspect` выводит недоверенные данные, не проверяет подпись и явно предупреждает об этом. LWT-обёртка пока не реализована; перечисления алгоритмов в черновых модулях не означают поддержку этих алгоритмов CLI.

```bash
cargo test --locked --all-targets
cargo build --locked --release
./target/release/jwt-lab --key /secure/path/jwtgate.key init
./target/release/jwt-lab --key /secure/path/jwtgate.key issue --sub alice --ttl 3600 --role reader
./target/release/jwt-lab --key /secure/path/jwtgate.key verify '<token>'
./target/release/jwt-lab inspect '<token>'
```

`init` создаёт случайный 256-битный ключ и никогда не перезаписывает существующий файл. На Unix запрашиваются права `0600`; размещайте ключ на файловой системе, которая поддерживает эти права. На Windows настройте ACL каталога ключей. Ключи исключены из Git. Аргументы токена могут попадать в историю оболочки: используйте демонстрационные токены при ручном запуске.

Проверено на Rust 1.98.1. Четыре теста проверяют HMAC-вектор RFC 4231, выпуск/проверку, отказ для неверного ключа/алгоритма/издателя/просроченного токена и сохранение существующего ключа.

## Что ещё требуется

- Определить формат и модель угроз LWT до реализации envelope.
- Отделить и проверить экспериментальные модели JOSE: сейчас CLI их не использует.
- Добавить отдельную политику аудитории и прикладных прав для интеграции в сервер.
- Провести interoperability и fuzz-тесты перед использованием как инфраструктурного компонента.

Статус: исследовательская разработка, не готовый SDK. Лицензия: [AGPL-3.0](LICENSE). [English](README.en.md).
