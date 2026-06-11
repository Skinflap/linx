# Maintainer: Mitchell <skinflap>
pkgname=linx
pkgver=1.1.0
pkgrel=1
pkgdesc="Linux driver for the Lian Li 8.8\" Universal LCD Screen"
arch=('any')
url="https://github.com/Skinflap/linx"
license=('Unlicense')
depends=(
    'python'
    'python-pyusb'
    'python-pycryptodome'
    'python-pillow'
    'ffmpeg'
)
optdepends=(
    'python-gobject: GUI'
    'libadwaita: GUI'
)
makedepends=(
    'python-build'
    'python-installer'
    'python-setuptools'
    'python-wheel'
)
source=("git+https://github.com/Skinflap/linx.git")
sha256sums=('SKIP')
install=linx.install

build() {
    cd "$srcdir/linx"
    python -m build --wheel --no-isolation
}

package() {
    cd "$srcdir/linx"
    python -m installer --destdir="$pkgdir" dist/*.whl

    # udev rules
    install -Dm644 dist/linx.udev "$pkgdir/usr/lib/udev/rules.d/70-linx.rules"

    # systemd user service
    install -Dm644 dist/linx.service "$pkgdir/usr/lib/systemd/user/linx.service"

    # default config
    install -Dm644 dist/linx.conf.default "$pkgdir/etc/linx.conf"

    # desktop entry
    install -Dm644 dist/linx.desktop "$pkgdir/usr/share/applications/linx.desktop"

    # application icon
    install -Dm644 dist/linx.svg "$pkgdir/usr/share/icons/hicolor/scalable/apps/linx.svg"

    # license
    install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
