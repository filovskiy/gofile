// gofile — конфигурация.
//
// token: fine-grained PAT (Contents: Read and write, только репозиторий gofile).
// Нужен ТОЛЬКО для загрузки файлов. Скачивание всегда анонимно.
// Чтобы разрешить загрузки всем посетителям — вставьте токен сюда и закоммитьте.
// Где создать: GitHub → Settings → Developer settings → Fine-grained tokens → Generate.
//   Repository access: only gofile; Permissions → Contents: Read and write.
//
// Важно: токен в публичном репозитории виден всем. Он даёт право менять содержимое
// ТОЛЬКО этого репозитория — отдавайте токен с доступом исключительно к gofile.
window.GOFILE_CONFIG = {
  owner: 'filovskiy',          // владелец репозитория-хранилища
  repo: 'gofile',              // репозиторий-хранилище
  branch: 'main',
  token: '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',                   // <-- вставьте токен сюда, чтобы включить загрузки
  maxBytes: 40 * 1024 * 1024,  // лимит размера файла (GitHub Contents API)
  ttlDays: 7                   // срок хранения; синхронизирован с purge.yml
};
