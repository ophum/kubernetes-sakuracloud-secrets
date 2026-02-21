#!/bin/bash

# NOTE
# 複数人での開発においてツールのバージョンを固定したい。
# go installを利用する場合、ほかのプロジェクトでインストールしたバージョンが利用される可能性がある。
# go toolを利用する場合、プロジェクトのgo.modの依存関係に影響される可能性がある。
# そのため、GOBINを./binに設定しgo installすることでプロジェクトに閉じるようにし、
# go installをスクリプト内で行うことでバージョンを固定する

cmd=$1
shift

case $cmd in
    "pinact")
        pkg=github.com/suzuki-shunsuke/pinact/v3/cmd/pinact@v3.9.0
        ;;
    *)
        echo "invalid command: $cmd"
        exit 1
        ;;
esac

export GOBIN=$(pwd)/bin
go install $pkg

exec $GOBIN/$cmd "$@"