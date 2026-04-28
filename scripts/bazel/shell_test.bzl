def _shell_test_impl(ctx):
    runner = ctx.actions.declare_file(ctx.label.name + "_runner.sh")
    ctx.actions.write(
        output = runner,
        content = """#!/usr/bin/env bash
set -euo pipefail
exec "$TEST_SRCDIR/$TEST_WORKSPACE/{script}" "$@"
""".format(script = ctx.file.src.short_path),
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = ctx.files.data + [ctx.file.src])
    return [DefaultInfo(executable = runner, runfiles = runfiles)]

shell_test = rule(
    implementation = _shell_test_impl,
    attrs = {
        "src": attr.label(
            allow_single_file = True,
            executable = True,
            cfg = "target",
        ),
        "data": attr.label_list(allow_files = True),
    },
    test = True,
)
