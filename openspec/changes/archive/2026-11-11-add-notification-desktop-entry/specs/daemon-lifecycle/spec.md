# Spec Delta

## ADDED Requirements

### Requirement: Поставка desktop-файла приложения
The system SHALL поставлять в deb-пакете desktop-файл `/usr/share/applications/swapnotif.desktop` (`Type=Application`, `NoDisplay=true`), чтобы менеджер уведомлений резолвил отправителя `desktop-entry = "swapnotif"` сразу после установки пакета без дополнительных действий пользователя.

#### Scenario: Установка пакета кладёт desktop-файл
- **WHEN** deb-пакет установлен
- **THEN** файл `/usr/share/applications/swapnotif.desktop` существует, объявляет приложение с идентификатором `swapnotif` и не отображается в меню приложений (`NoDisplay=true`)

#### Scenario: Удаление пакета убирает desktop-файл
- **WHEN** deb-пакет удаляется
- **THEN** desktop-файл удаляется стандартными средствами dpkg, без скриптов пакета
