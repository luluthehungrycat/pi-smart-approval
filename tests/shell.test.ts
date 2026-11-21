import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeShell } from '../src/shell.ts';

test('recognizes the narrow routine allowlist', () => {
  const cases: Array<[string, string, string[]]> = [
    ['pwd', 'auto', []], ['ls -la src', 'auto', ['src']], ['ls', 'auto', []],
    ['cat README.md', 'auto', ['README.md']], ['head -n 20 a.txt', 'auto', ['a.txt']],
    ['tail -5 a.txt', 'auto', ['a.txt']], ['wc -l a b', 'auto', ['a', 'b']],
    ["echo 'a;b' c", 'auto', []], ['grep -rn TODO src', 'model', ['src']],
    ['grep -e -x src', 'model', ['src']], ["find src -name '*.ts' -type f", 'model', ['src']],
    ['diff -u a b', 'auto', ['a', 'b']], ['uname -a', 'auto', []],
    ['ls\t-la', 'auto', []],
  ];
  for (const [command, routine, paths] of cases) {
    const result = analyzeShell(command);
    assert.equal(result.simple, true, command);
    assert.equal(result.routine, routine, command);
    assert.deepEqual(result.paths, paths, command);
  }
  assert.deepEqual(analyzeShell("echo 'a;b' c").argv, ['echo', 'a;b', 'c']);
});

test('keeps literal simple commands outside routine grammars', () => {
  for (const command of [
    'git status', 'npm test', 'rm a', 'tail -f log', 'cat', 'cat -', 'grep TODO',
    'find . -delete', 'date -s x', 'pwd -P', 'ls --color', 'head -n x a',
  ]) {
    const result = analyzeShell(command);
    assert.equal(result.simple, true, command);
    assert.equal(result.routine, undefined, command);
    assert.deepEqual(result.paths, [], command);
  }
  const compoundFind = analyzeShell('find . -exec rm {} ;');
  assert.equal(compoundFind.simple, false);
  assert.deepEqual(compoundFind.argv, []);
  assert.deepEqual(analyzeShell('ls -- -weird').paths, []);
  assert.equal(analyzeShell('ls -- -weird').routine, undefined);
});

test('rejects shell syntax, ambiguous characters, and invalid program names', () => {
  const commands = [
    'ls; rm x', 'ls && x', 'ls | sh', 'ls > f', 'cat < f', 'echo $(x)', 'echo `x`',
    'echo $HOME', 'ls *', 'ls ~', 'ls ~/x', 'A=1 ls', "'ls'", '/bin/ls', 'LS',
    'echo "x"', 'echo \\x', 'ls\nrm x', 'ls -la', 'ls‮', "echo 'unterminated", "''", '',
    'x'.repeat(2001), 'ls {a,b}', 'ls a#b', 'ls !x',
  ];
  for (const command of commands) {
    const result = analyzeShell(command);
    assert.equal(result.simple, false, JSON.stringify(command));
    assert.deepEqual(result.argv, [], JSON.stringify(command));
    assert.deepEqual(result.paths, [], JSON.stringify(command));
    assert.equal(result.routine, undefined, JSON.stringify(command));
  }
});
