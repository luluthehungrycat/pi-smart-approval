export type RoutineTier = 'auto' | 'model';

export interface ShellAnalysis {
  simple: boolean;
  argv: string[];
  routine?: RoutineTier;
  paths: string[];
  reason: string;
}

const notSimple = (reason: string): ShellAnalysis => ({ simple: false, argv: [], paths: [], reason });
const pathOperand = (word: string): boolean => word !== '' && word !== '-' && !word.startsWith('-');
const flags = (word: string, pattern: RegExp): boolean => pattern.test(word);

function routineFor(argv: string[]): Pick<ShellAnalysis, 'routine' | 'paths' | 'reason'> {
  const [program, ...args] = argv;
  const none = (reason: string) => ({ paths: [], reason });
  const auto = (paths: string[] = []) => ({ routine: 'auto' as const, paths, reason: 'Matches the conservative automatic routine allowlist.' });
  const model = (paths: string[]) => ({ routine: 'model' as const, paths, reason: 'Matches the conservative model-reviewed routine allowlist.' });
  const allPaths = (xs: string[]) => xs.length > 0 && xs.every(pathOperand);

  if (['pwd', 'true', 'whoami', 'date'].includes(program)) return args.length === 0 ? auto() : none('Arguments are outside the routine grammar.');
  if (program === 'echo') return auto();
  if (program === 'uname') return args.every(x => flags(x, /^-[asnrvmpio]+$/)) ? auto() : none('Arguments are outside the routine grammar.');
  if (program === 'ls') {
    let i = 0;
    while (i < args.length && args[i] !== '--' && args[i].startsWith('-')) {
      if (!flags(args[i], /^-[1aAlhRtrSdFp]+$/)) return none('Arguments are outside the routine grammar.');
      i++;
    }
    if (args[i] === '--') i++;
    const operands = args.slice(i);
    return operands.every(pathOperand) ? auto(operands) : none('Path operands are outside the routine grammar.');
  }
  if (program === 'cat' || program === 'wc' || program === 'file' || program === 'du' || program === 'stat') {
    let i = 0;
    const pattern = program === 'cat' ? /^-[nbAEsvT]+$/ : program === 'wc' ? /^-[lwcmL]+$/ : program === 'file' ? /^-[bL]+$/ : program === 'du' ? /^-[shca]+$/ : /^$/;
    while (i < args.length && args[i].startsWith('-') && args[i] !== '-') {
      if (!pattern.test(args[i])) return none('Arguments are outside the routine grammar.');
      i++;
    }
    const operands = args.slice(i);
    if (program === 'du') return operands.every(pathOperand) ? auto(operands) : none('Path operands are outside the routine grammar.');
    return allPaths(operands) ? auto(operands) : none('At least one valid path operand is required.');
  }
  if (program === 'head' || program === 'tail') {
    const operands: string[] = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (/^-[0-9]+$/.test(a) || /^-[nc][0-9]+$/.test(a)) continue;
      if (a === '-n' || a === '-c') {
        if (++i >= args.length || !/^[0-9]+$/.test(args[i])) return none('Arguments are outside the routine grammar.');
        continue;
      }
      if (!pathOperand(a)) return none('Arguments are outside the routine grammar.');
      operands.push(a);
    }
    return allPaths(operands) ? auto(operands) : none('At least one valid path operand is required.');
  }
  if (program === 'grep') {
    let i = 0;
    while (i < args.length && args[i] !== '-e' && args[i].startsWith('-')) {
      if (!flags(args[i], /^-[inrwlcHhvEFoqs]+$/)) return none('Arguments are outside the routine grammar.');
      i++;
    }
    if (args[i] === '-e') i++;
    if (i >= args.length) return none('A pattern and at least one path are required.');
    i++;
    const operands = args.slice(i);
    return allPaths(operands) ? model(operands) : none('A pattern and at least one valid path are required.');
  }
  if (program === 'find') {
    let i = 0;
    while (i < args.length && !args[i].startsWith('-')) i++;
    const roots = args.slice(0, i);
    if (!allPaths(roots)) return none('At least one valid starting path is required.');
    while (i < args.length) {
      const pred = args[i++];
      if (['-name', '-iname', '-path', '-ipath'].includes(pred)) {
        if (i >= args.length) return none('Predicate value is missing.');
        i++;
      } else if (pred === '-type') {
        if (!['f', 'd', 'l'].includes(args[i++] ?? '')) return none('Predicate value is outside the routine grammar.');
      } else if (pred === '-maxdepth' || pred === '-mindepth') {
        if (!/^[0-9]+$/.test(args[i++] ?? '')) return none('Predicate value is outside the routine grammar.');
      } else if (pred !== '-print') return none('Predicate is outside the routine grammar.');
    }
    return model(roots);
  }
  if (program === 'diff') {
    let i = 0;
    while (i < args.length && args[i].startsWith('-')) {
      if (!flags(args[i], /^-[uqrNwb]+$/)) return none('Arguments are outside the routine grammar.');
      i++;
    }
    const operands = args.slice(i);
    return operands.length === 2 && operands.every(pathOperand) ? auto(operands) : none('Exactly two valid path operands are required.');
  }
  return none('Command is outside the routine allowlist.');
}

export function analyzeShell(command: string): ShellAnalysis {
  if (typeof command !== 'string') return notSimple('Command must be a string.');
  const trimmed = command.replace(/^[ \t]+|[ \t]+$/g, '');
  if (trimmed.length < 1 || trimmed.length > 2000) return notSimple('Command length is outside 1..2000 characters.');
  for (let i = 0; i < trimmed.length; i++) {
    const code = trimmed.charCodeAt(i);
    if (code > 0x7e || code < 0x20 && code !== 0x20 && code !== 0x09 || code === 0x7f) return notSimple('Command contains non-ASCII, control, or unsupported whitespace.');
  }
  const words: string[] = [];
  let word = '', active = false, firstWordQuoted = false;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i]!;
    if (c === ' ' || c === '\t') {
      if (active) { words.push(word); word = ''; active = false; }
      continue;
    }
    if (c === '"' || c === '\\') return notSimple('Double quotes and escapes are unsupported.');
    if (c === "'") {
      if (words.length === 0 && !active) firstWordQuoted = true;
      active = true;
      const end = trimmed.indexOf("'", i + 1);
      if (end < 0) return notSimple('Unterminated single quote.');
      word += trimmed.slice(i + 1, end);
      i = end;
      continue;
    }
    if (!/[A-Za-z0-9_./=:,@%+-]/.test(c)) return notSimple('Command contains shell syntax or unsupported characters.');
    active = true;
    word += c;
  }
  if (active) words.push(word);
  if (words.length === 0 || firstWordQuoted || words[0] === '' || !/^[a-z][a-z0-9._+-]{0,63}$/.test(words[0]!)) return notSimple('Program name must be an unquoted lowercase literal.');
  const decision = routineFor(words);
  return { simple: true, argv: words, ...decision };
}
