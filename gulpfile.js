/* ==========================================================================
   Gulp-сборка веб-интерфейса dsc-vfs-solvent.

   Исходники:  src/dsc_vfs_solvent/web/src/   (TypeScript + CSS)
   Результат:  src/dsc_vfs_solvent/web/dist/  (минифицированные assets)

   Сборка JS выполняется через esbuild: TypeScript + Vue (npm-пакет)
   бандлятся в единый app.min.js, CDN не используется.

   Задачи:
     gulp build   — полная сборка (CSS + JS)
     gulp watch   — пересборка при изменении исходников
     gulp clean   — удаление каталога dist
   ========================================================================== */

"use strict";

const gulp = require("gulp");
const postcss = require("gulp-postcss");
const sourcemaps = require("gulp-sourcemaps");
const autoprefixer = require("autoprefixer");
const cssnano = require("cssnano");
const del = require("del");
const esbuild = require("esbuild");

const SRC_DIR = "src/dsc_vfs_solvent/web/src";
const DIST_DIR = "src/dsc_vfs_solvent/web/dist";

// -- CSS: автопрефиксы + минификация + sourcemap -------------------------
function styles() {
  return gulp
    .src(`${SRC_DIR}/styles.css`)
    .pipe(sourcemaps.init())
    .pipe(postcss([autoprefixer(), cssnano()]))
    .pipe(sourcemaps.write("."))
    .pipe(gulp.dest(DIST_DIR));
}

// -- Bootstrap: локальная копия (без CDN) ---------------------------------
function bootstrap() {
  return gulp
    .src("node_modules/bootstrap/dist/css/bootstrap.min.css")
    .pipe(gulp.dest(DIST_DIR));
}

// -- JS: esbuild (TypeScript + Vue → единый бандл app.min.js) ------------
async function scripts() {
  await esbuild.build({
    entryPoints: [`${SRC_DIR}/app.ts`],
    bundle: true,
    minify: true,
    sourcemap: true,
    target: ["es2020"],
    format: "iife",
    outfile: `${DIST_DIR}/app.min.js`,
  });
}

// -- Очистка -------------------------------------------------------------
function clean() {
  return del([DIST_DIR]);
}

// -- Наблюдение ----------------------------------------------------------
function watch() {
  gulp.watch(`${SRC_DIR}/styles.css`, styles);
  gulp.watch(`${SRC_DIR}/app.ts`, scripts);
}

const build = gulp.series(clean, gulp.parallel(styles, scripts, bootstrap));

exports.styles = styles;
exports.scripts = scripts;
exports.bootstrap = bootstrap;
exports.clean = clean;
exports.watch = watch;
exports.build = build;
exports.default = build;