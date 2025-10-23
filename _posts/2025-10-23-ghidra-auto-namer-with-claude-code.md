---
layout: post
title: "Scripting Ghidra to auto rename functions and variables with an LLM"
date: 2025-10-23
excerpt: "Using Claude Code to automate the labeling of a >10,000-function firmware dump, with some sample results and the script."
has_ai: true
comments: true
---

**TL;DR**: I wrote a Ghidra script that uses the Claude Code CLI to automatically rename functions and variables in disassembled binaries. [Jump to the full script](#the-script) or [the examples](#what-the-results-look-like) if you want to skip the story.

---

I have very little experience "reverse engineering" (I usually prefer to be the one doing the engineering, not undoing someone else's). Alas, I was recently [nerd sniped](https://xkcd.com/356) by a friend in possession of some automotive hardware. With their firmware dumps in hand and a bit of time to kill (but very little dignity left to lose), I installed Ghidra and set out attempting to wrap my head around the disassembly.

Naturally, the function and variable names were completely mangled and unidentifiable: `FUN_00123456`, `DAT_00abcdef`, and other designations that seemed to suggest the original developer had let their cat walk across the keyboard. I set up the fantastic [Ghidra MCP](https://github.com/LaurieWired/GhidraMCP), and while it did an astounding job of making sense of code that may as well have been hieroglyphics written by someone who'd only seen hieroglyphics described to them over a poor phone connection, there was only so much an LLM could do when searching through 5,000-10,000 unnamed functions per binary.

But I noticed something interesting: the LLMs I tried seemed shockingly good at making reasonable guesses about what the code was doing, even with limited context. So naturally, I did what any reasonable person would do - I (attempted to) automate the problem away. Enter: Claude Code, "please write a Ghidra script that automatically renames functions and variables using `claude --print`".

## The Problem

Let me be very clear upfront: **I cannot vouch for the accuracy of these results**. I have essentially no reverse engineering experience. But the names the script generates seem shockingly convincing, and they've made navigating these binaries infinitely less painful. Your mileage may vary. Use at your own risk. Don't blame me if Claude decides your cryptographic functions are actually sandwich-making routines.

That said, here's what I was dealing with:
- 5,000-10,000 functions per binary
- Almost every single one named `FUN_[address]`
- Local variables named things like `iVar3`, `fVar1`, `param_2`
- Global variables as `DAT_[address]`
- Zero context about what any of it does

Reading through this manually is possible. It's also approximately as fun as alphabetizing your sock drawer while someone reads you the phone book. And when you're trying to understand a complex system by jumping between functions, keeping track of what `FUN_00fe0db4` does vs `FUN_00fdf948` is a special kind of cognitive torture.

## How It Works

The script is surprisingly straightforward:

1. **Find unnamed functions**: Scan the binary for anything starting with `FUN_`
2. **Decompile to C**: Use Ghidra's decompiler to get pseudo-C code
3. **Ask Claude**: Ship that code to `claude --print` with a prompt asking for better names
4. **Apply renames**: Parse Claude's JSON response and rename the function, its variables, and any globals it touches
5. **Repeat**: Do this in parallel batches (I used 60 concurrent requests) until you run out of functions

The script tries not to rename a function until all the functions it calls have been renamed first. This means it processes the codebase bottom-up, starting with leaf functions and working toward more complex ones. By the time Claude sees a function that calls `calculateAngleFromEncoder()` and `applyPIDCorrection()`, those have already been renamed with meaningful names - which I'd imagine gives it way better context.

There's also retry logic, timeout handling, and checkpoint commits so you don't lose progress if something explodes (which, at the beginning, it did several times).

## The Claude Max Requirement

Here's something important: running this script on a large binary chews through my token budget. We're talking about sending hundreds of lines of decompiled C code for thousands of functions. I ended up needing Claude's "Max" plan ($200/month) which advertises 20x higher usage limits compared to the base $20/month Pro plan.

Even with the Max plan, processing a 10,000-function binary takes over an hour with 60 concurrent threads and burns through serious tokens. In my case, processing a large firmware dump consumed almost 20% of my "weekly usage limit". This isn't a casual "let's try it on a weekend" project if you're on the free tier or even the Pro plan. Budget accordingly.

## What the Results Look Like

Let me show you three real examples from the automotive firmware I was analyzing. These transformations happened automatically - no manual intervention, just Claude Code staring at decompiled C and making educated guesses.

### Example 1: Trigonometry with Sector Calculations

**Before: `FUN_00fe0db4`**

```c
void FUN_00fe0db4(float param_1,float *param_2,float *param_3)
{
  float fVar1;
  ulonglong uVar2;
  int iVar4;
  ulonglong in_r12;
  longlong lVar5;
  uint uVar3;

  fVar1 = param_1 * 1.9098593 + 0.5;
  if (fVar1 < 0.0) {
    uVar2 = (ulonglong)-fVar1;
    if (0x80000000 < uVar2) {
      uVar2 = 0x80000000;
    }
    uVar3 = -(int)uVar2;
  }
  else {
    uVar2 = (ulonglong)fVar1;
    if (0x7fffffff < uVar2) {
      uVar2 = 0x7fffffff;
    }
    uVar3 = (uint)uVar2;
  }
  // ... 60 more lines of float arithmetic and switch cases ...
}
```

**After: `computeSinCos`**

```c
void computeSinCos(float angleRadians,float *outSine,float *outCosine)
{
  float fVar1;
  float fVar2;
  int normalizedSector;
  ulonglong in_r12;
  longlong sectorIndex;
  uint scaledAngleInt;
  ulonglong absValue;

  fVar1 = angleRadians * 1.9098593 + 0.5;
  if (fVar1 < 0.0) {
    absValue = (ulonglong)-fVar1;
    if (0x80000000 < absValue) {
      absValue = 0x80000000;
    }
    scaledAngleInt = -(int)absValue;
  }
  // ... continues with readable variable names ...
}
```

Look at those variable names. `angleRadians`, `outSine`, `outCosine`, `normalizedSector` - these seem like reasonable guesses. Claude appears to have spotted the magic number `1.9098593` (which might be approximately 6/π, potentially for converting radians to sectors?), and what look like Taylor series approximations in the code. Based on these patterns, it identified this as a trig function implementation - which honestly seems pretty plausible to me, though I'm not experienced enough to say for certain. The sector-based switch statement might make sense in the context of embedded systems that use lookup tables for speed.

### Example 2: Kinematics with Small Acceleration

**Before: `FUN_00fdf948`**

```c
void FUN_00fdf948(float *param_1,float param_2,float param_3,float param_4)
{
  float fVar1;

  if (ABS(param_4) <= 0.001) {
    fVar1 = param_2 * param_2 * param_4 * 0.5;
    *param_1 = param_2;
    param_1[1] = fVar1;
    param_1[2] = param_3 - fVar1;
    param_1[3] = param_2;
    FUN_010a4faa();
    return;
  }
  halt_baddata();
}
```

**After: `computeLinearMotionWithSmallAcceleration`**

```c
void computeLinearMotionWithSmallAcceleration
               (float *outputArray,float velocity,float initialPosition,float acceleration)
{
  float displacementTerm;

  if (ABS(acceleration) <= 0.001) {
    displacementTerm = velocity * velocity * acceleration * 0.5;
    *outputArray = velocity;
    outputArray[1] = displacementTerm;
    outputArray[2] = initialPosition - displacementTerm;
    outputArray[3] = velocity;
    noOperation();
    return;
  }
  halt_baddata();
}
```

This one seems pretty reasonable too, though I'm speculating here. Claude appears to have recognized what might be the kinematic equation `displacement = velocity² × acceleration / 2` for displacement under constant acceleration. The threshold check `ABS(acceleration) <= 0.001` suggests this could be a special case handler for near-zero acceleration, where you'd want to use a simpler calculation to avoid numerical instability (I think?). In automotive firmware, this would make sense - you're probably constantly computing motion profiles for throttle control, steering, or motor positioning. At least, that's my guess based on the patterns I'm seeing.

### Example 3: 2D Transformation Composition

**Before: `FUN_00fde3ec`**

```c
void FUN_00fde3ec(undefined4 *param_1,int *param_2,int *param_3)
{
  float fVar1;
  float fVar2;
  int iVar3;
  float fVar4;
  float fVar5;
  undefined4 uVar6;
  float fVar7;
  float fVar8;

  if (*param_2 == 2) {
    fVar7 = (float)param_2[2];
    fVar5 = (float)param_2[4];
    if (*param_3 == 2) {
      fVar4 = 1.0;
      fVar8 = 0.0;
      fVar7 = fVar7 + (float)param_3[2];
      fVar5 = fVar5 + (float)param_3[4];
      uVar6 = 2;
    }
    // ... 70+ more lines of nested conditionals ...
  }
}
```

**After: `composeTransform2D`**

```c
void composeTransform2D(undefined4 *outTransform,int *transform1,int *transform2)
{
  float cosTheta1;
  float outTranslationY;
  undefined4 outTransformType;
  float outTranslationX;
  float outSinTheta;
  float cosTheta2;
  float sinTheta1;
  int transform2Type;

  if (*transform1 == 2) {
    outTranslationX = (float)transform1[2];
    outTranslationY = (float)transform1[4];
    if (*transform2 == 2) {
      cosTheta1 = 1.0;
      outSinTheta = 0.0;
      outTranslationX = outTranslationX + (float)transform2[2];
      outTranslationY = outTranslationY + (float)transform2[4];
      outTransformType = 2;
    }
    // ... continues with clear variable names ...
  }
}
```

This function appears to compose 2D transformations (likely for sensor fusion or display coordinate mapping, though that's just my interpretation). The type field seems to indicate whether it's a pure translation (type 2), pure rotation (type 1), or full rigid transform (type 0) - at least based on the patterns in the code. Claude appears to have spotted the pattern of checking transform types and combining translations, rotations (using sin/cos), and full transforms appropriately. Variables like `cosTheta1`, `transform2Type`, `outTranslationX` make the logic way more navigable than `fVar4`, `iVar3`, and `param_2` did, even if the names aren't 100% accurate.

## Why This Seems To Work

I think there are a few reasons LLMs might be surprisingly good at this - though these are just my theories based on limited experience:

**1. Decompilers seem to produce consistent patterns**: Ghidra's output appears pretty systematic. Variables seem to get predictable names (`iVar1`, `fVar2`). Control flow seems to be normalized. This consistency probably helps the LLM spot patterns.

**2. Math provides strong hints**: When you see `param_1 * 1.9098593` or `velocity * velocity * acceleration * 0.5`, there probably aren't that many things it could plausibly be. Mathematical constants and formulas seem like strong signals?

**3. Context accumulates**: By processing functions bottom-up, Claude gets to see increasingly meaningful variable names as it works through the call graph. I'd imagine a function that calls `computeSinCos()` is much easier to understand than one that calls `FUN_00fe0db4()`.

**4. LLMs seem good at "code that looks like math"**: These automotive functions are heavy on numerical computation and physics simulation. While LLMs are notoriously bad at math, that's probably the kind of code that's well-represented in training data and has clearer semantic meaning than, say, complex business logic or state machines.

## Caveats and Gotchas

Let's be clear, a lot can go wrong:

**It will make mistakes**. Claude is guessing. Sometimes it's an educated guess based on solid patterns. Sometimes it's creative fiction.

**It's slow**. Even with 60 concurrent requests, processing a 10k-function binary took me over an hour. It used almost 20% of my weekly token. Budget time and tokens accordingly.

**Circular dependencies exist**. Sometimes functions call each other in loops. The script tries to detect this and force-process the functions with the fewest dependencies, but it means that the LLM will not have the full context it could have had.

**Claude doesn't know your domain**. If you're reversing firmware for a really obscure piece of hardware, Claude's guesses might (very likely) be plain wrong. It helps if the code uses common patterns, but specialized domain knowledge is not something LLMs excel at without extra help.

## Should You Use This?

If you're staring at thousands of unnamed functions and losing your mind, yes. Absolutely yes. Even if the names are only 50% accurate, it felt to me infinitely better than `FUN_00123456`. You'll spend less time memorizing addresses and more time actually understanding the code.

If you're doing serious security research where correctness matters, be careful. Use this as a starting point, not gospel. Verify everything. This is obvious to everyone working in software at this point, but to reiterate: very rarely does the LLM know better than you.

If you're on a budget, be aware of the token costs. This script is not cheap to run on large binaries. The Claude Max plan exists for a reason.

## The Script

Here's the full script. Drop it in your Ghidra scripts directory, update the configuration section at the top with your Claude path and token, and run it from the Script Manager.

```python
# -*- coding: utf-8 -*-
# Ghidra Function Auto-Namer using Claude Code CLI
# @author Matt Webb + Claude Code
# @category Analysis
# @keybinding
# @menupath Tools.Claude Function Namer
# @toolbar

import os
import re
import json
import time
import java.io.BufferedReader as BufferedReader
import java.io.InputStreamReader as InputStreamReader
import java.lang.ProcessBuilder as ProcessBuilder
import java.util.concurrent.TimeUnit as TimeUnit
import java.util.ArrayList as ArrayList
import java.util.concurrent.Executors as Executors
import java.util.concurrent.Callable as Callable
import java.util.concurrent.TimeoutException as TimeoutException
import java.util.concurrent.ExecutionException as ExecutionException
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.pcode import HighFunctionDBUtil
from ghidra.util.exception import DuplicateNameException

# --- CONFIGURATION ---
CLAUDE_PATH = "/opt/homebrew/bin/claude"
CLAUDE_OAUTH_TOKEN = os.environ["CLAUDE_CODE_OAUTH_TOKEN"]
CONCURRENCY = 30  # Number of parallel Claude API calls
PROMPT_SUFFIX = "<additional info to add to the prompt about the binary>"
# --- END CONFIGURATION ---

def get_decompiled_code(function, decompiler):
    """Decompile a function and return its C code and decompile results."""
    try:
        results = decompiler.decompileFunction(function, 60, monitor)
        if not results or not results.decompileCompleted():
            return None, None

        decomp = results.getDecompiledFunction()
        if not decomp:
            return None, None

        c_code = decomp.getC()
        if not c_code or len(c_code.strip()) == 0:
            return None, None

        return c_code, results
    except Exception as e:
        print("Decompilation exception: {}".format(e))
        return None, None

def is_valid_function_to_rename(function):
    """Check if a function is worth renaming."""
    if function.isThunk() or function.isExternal():
        return False
    return True

def calls_unnamed_functions(function):
    """Check if a function calls any other FUN_ functions (excluding itself for recursion)."""
    try:
        called_functions = function.getCalledFunctions(monitor)
        function_addr = function.getEntryPoint()

        for called_func in called_functions:
            if called_func.getEntryPoint().equals(function_addr):
                continue

            if called_func.getName().startswith("FUN_"):
                return True

        return False
    except Exception as e:
        print("  -> WARNING: Error checking dependencies for {}: {}".format(function.getName(), e))
        return False

def get_unnamed_functions(func_manager):
    """Get all functions that start with FUN_ and are valid for renaming."""
    unnamed_funcs = []
    for function in func_manager.getFunctions(True):
        if function.getName().startswith("FUN_"):
            if is_valid_function_to_rename(function):
                unnamed_funcs.append(function)
    return unnamed_funcs

def query_claude_for_name(decompiled_code, claude_path):
    """Call Claude Code CLI to get suggestions for function and variable names."""
    prompt = """{code}

Analyze the function above. Provide new, accurate names for the function, its local variables, and any global variables (DAT_*).
The function name must be camelCase.

{suffix}

Respond *only* with a valid JSON object in the following format:

{{
  "functionName": "descriptiveFunctionName",
  "variableNames": {{
    "oldVarName": "newVarName"
  }},
  "globalVariableNames": {{
    "DAT_00123456": "descriptiveGlobalName"
  }}
}}

Only include variable mappings you have high confidence in. If unsure, exclude it.

JSON Response:
""".format(code=decompiled_code, suffix=PROMPT_SUFFIX)

    max_retries = 3

    for attempt in range(max_retries):
        try:
            cmd_list = ArrayList()
            cmd_list.add(claude_path)
            cmd_list.add("--print")
            cmd_list.add("--dangerously-skip-permissions")
            cmd_list.add("--disallowed-tools")
            cmd_list.add("Bash,Edit,Write,FileSystem")

            builder = ProcessBuilder(cmd_list)
            if CLAUDE_OAUTH_TOKEN and len(CLAUDE_OAUTH_TOKEN.strip()) > 0:
                builder.environment().put("CLAUDE_CODE_OAUTH_TOKEN", CLAUDE_OAUTH_TOKEN)
            builder.redirectErrorStream(True)

            process = builder.start()

            output_stream = process.getOutputStream()
            output_stream.write(prompt.encode('utf-8'))
            output_stream.close()

            reader = BufferedReader(InputStreamReader(process.getInputStream(), "UTF-8"))
            output_lines = []
            line = reader.readLine()
            while line is not None:
                output_lines.append(line)
                line = reader.readLine()
            reader.close()

            finished = process.waitFor(120, TimeUnit.SECONDS)

            if not finished:
                continue

            exit_code = process.exitValue()
            raw_output = "\n".join(output_lines).strip()

            if exit_code != 0:
                continue

            json_string = re.sub(r'^```.*?\n', '', raw_output)
            json_string = re.sub(r'\n```$', '', json_string)
            json_string = json_string.strip()

            try:
                data = json.loads(json_string)

                suggested_name = data.get("functionName")
                variable_mappings = data.get("variableNames", {})
                global_mappings = data.get("globalVariableNames", {})

                if not suggested_name or not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', suggested_name):
                    continue

                return (suggested_name, variable_mappings, global_mappings)

            except ValueError:
                continue

        except Exception:
            continue

    return (None, None, None)

def rename_function(function, new_name):
    """Rename a function in Ghidra - NO transaction, relies on outer transaction."""
    try:
        old_name = function.getName()
        function.setName(new_name, SourceType.USER_DEFINED)
        print("  -> Renamed {} -> {}".format(old_name, new_name))
        return True
    except Exception as e:
        print("  -> Error renaming function: {}".format(e))
        return False

def rename_variables(function, variable_mappings, decompile_results):
    """Rename function variables - NO transaction, relies on outer transaction."""
    if not variable_mappings:
        return

    print("  -> Renaming {} local variables...".format(len(variable_mappings)))

    try:
        high_function = decompile_results.getHighFunction()
        if not high_function:
            return

        lsymMap = high_function.getLocalSymbolMap()
        if not lsymMap:
            return

        symbols = lsymMap.getSymbols()
        for sym in symbols:
            old_name = sym.getName()
            if old_name in variable_mappings:
                new_name = variable_mappings[old_name]

                if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name):
                    continue

                if old_name == new_name:
                    continue

                attempted_name = new_name
                attempt_count = 0
                max_attempts = 50

                while attempt_count < max_attempts:
                    try:
                        HighFunctionDBUtil.updateDBVariable(
                            sym,
                            attempted_name,
                            None,
                            SourceType.USER_DEFINED
                        )
                        print("    {} -> {}".format(old_name, attempted_name))
                        break
                    except DuplicateNameException:
                        attempt_count += 1
                        attempted_name = "{}_{}".format(new_name, attempt_count)
                    except Exception as e:
                        print("    Error with {}: {}".format(old_name, str(e)))
                        break

    except Exception as e:
        print("  -> Error during variable rename: {}".format(e))

def rename_globals(program, global_mappings):
    """Rename global variables - NO transaction, relies on outer transaction."""
    if not global_mappings:
        return

    print("  -> Renaming {} global variables...".format(len(global_mappings)))

    symbol_table = program.getSymbolTable()

    for old_name, new_name in global_mappings.items():
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', new_name):
            continue

        try:
            symbols = symbol_table.getSymbols(old_name)
            if symbols and symbols.hasNext():
                symbol = symbols.next()

                attempted_name = new_name
                attempt_count = 0
                max_attempts = 50

                while attempt_count < max_attempts:
                    try:
                        symbol.setName(attempted_name, SourceType.USER_DEFINED)
                        print("    {} -> {}".format(old_name, attempted_name))
                        break
                    except DuplicateNameException:
                        attempt_count += 1
                        attempted_name = "{}_{}".format(new_name, attempt_count)
                    except Exception as e:
                        print("    Error with {}: {}".format(old_name, str(e)))
                        break

        except Exception as e:
            print("    Error with {}: {}".format(old_name, str(e)))

def format_time(seconds):
    """Format seconds into human-readable time."""
    if seconds < 60:
        return "{}s".format(int(seconds))
    elif seconds < 3600:
        return "{}m {}s".format(int(seconds / 60), int(seconds % 60))
    else:
        hours = int(seconds / 3600)
        minutes = int((seconds % 3600) / 60)
        return "{}h {}m".format(hours, minutes)

def initialize_decompiler(program):
    """Initialize the decompiler."""
    decompiler = DecompInterface()
    options = DecompileOptions()
    decompiler.setOptions(options)
    if not decompiler.openProgram(program):
        print("ERROR: Failed to initialize decompiler!")
        return None
    return decompiler

class ClaudeCallable(Callable):
    """Callable wrapper for Claude API calls."""
    def __init__(self, func, decomp_code, decomp_results, claude_path):
        self.func = func
        self.decomp_code = decomp_code
        self.decomp_results = decomp_results
        self.claude_path = claude_path

    def call(self):
        try:
            suggested_name, var_mappings, global_mappings = query_claude_for_name(
                self.decomp_code, self.claude_path)
            return (self.func, self.decomp_results, suggested_name, var_mappings, global_mappings)
        except Exception as e:
            print("  -> Error processing {}: {}".format(self.func.getName(), e))
            return (self.func, self.decomp_results, None, None, None)

def process_batch(batch_data, claude_path):
    """Process a batch of functions in parallel (Claude calls only)."""
    executor = Executors.newFixedThreadPool(CONCURRENCY)
    futures = []

    try:
        future_to_item = {}

        for item in batch_data:
            func, decomp_code, decomp_results = item
            callable_task = ClaudeCallable(func, decomp_code, decomp_results, claude_path)
            future = executor.submit(callable_task)
            futures.append(future)
            future_to_item[future] = item

        successful_results = []
        failed_items = []

        remaining_futures = list(futures)
        batch_start_time = time.time()
        per_future_timeout = 120
        max_batch_time = 150
        check_interval = 5

        while remaining_futures and (time.time() - batch_start_time) < max_batch_time:
            completed = []
            current_time = time.time()
            elapsed_time = current_time - batch_start_time

            batch_timed_out = elapsed_time > per_future_timeout

            for future in remaining_futures:
                try:
                    result = future.get(100, TimeUnit.MILLISECONDS)
                    successful_results.append(result)
                    completed.append(future)
                except TimeoutException:
                    if batch_timed_out:
                        original_item = future_to_item[future]
                        func, decomp_code, decomp_results = original_item
                        print("  -> Timeout for {}: exceeded {}s".format(
                            func.getName(), int(elapsed_time)))
                        failed_items.append(original_item)
                        completed.append(future)
                        future.cancel(True)
                except (ExecutionException, Exception) as e:
                    original_item = future_to_item[future]
                    func, decomp_code, decomp_results = original_item
                    print("  -> Error for {}: {}".format(func.getName(), str(e)[:100]))
                    failed_items.append(original_item)
                    completed.append(future)

            for future in completed:
                remaining_futures.remove(future)

            if batch_timed_out:
                break

            if remaining_futures:
                time.sleep(check_interval)

        for future in remaining_futures:
            original_item = future_to_item[future]
            func, decomp_code, decomp_results = original_item
            print("  -> Max batch time exceeded for {}".format(func.getName()))
            failed_items.append(original_item)
            future.cancel(True)

        return successful_results, failed_items
    finally:
        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)

def checkpoint_program(program, iteration):
    """Commit current transaction and start a new one to preserve changes."""
    try:
        print("  -> Creating checkpoint {} (committing transaction)...".format(iteration))
        program.flushEvents()
        end(True)
        start()
        print("  -> Checkpoint complete (changes committed)")
        return True
    except Exception as e:
        print("  -> Error creating checkpoint: {}".format(e))
        try:
            start()
        except:
            pass
        return False

def main():
    """Main function."""
    program = getCurrentProgram()
    func_manager = program.getFunctionManager()

    print("=" * 60)
    print("Claude Function Auto-Namer (Parallel)")
    print("=" * 60)
    print("Using Claude at: {}".format(CLAUDE_PATH))
    print("Concurrency: {}".format(CONCURRENCY))

    if not os.path.exists(CLAUDE_PATH):
        print("\nERROR: Claude executable not found at: {}".format(CLAUDE_PATH))
        return

    if not CLAUDE_OAUTH_TOKEN or "YOUR_TOKEN_HERE" in CLAUDE_OAUTH_TOKEN:
        print("\nERROR: CLAUDE_OAUTH_TOKEN is not set!")
        return

    decompiler = initialize_decompiler(program)
    if not decompiler:
        return

    initial_unnamed = get_unnamed_functions(func_manager)
    total_functions = len(initial_unnamed)
    print("Found {} unnamed functions to process\n".format(total_functions))

    total_renamed = 0
    total_failed = 0
    start_time = time.time()
    function_times = []

    retry_queue = {}
    MAX_RETRIES = 3

    max_iterations = 1000
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        unnamed_funcs = get_unnamed_functions(func_manager)

        if not unnamed_funcs and not retry_queue:
            print("\nNo more unnamed functions!")
            break

        if not unnamed_funcs and retry_queue:
            all_maxed_out = all(retry_count >= MAX_RETRIES for _, _, _, retry_count in retry_queue.values())
            if all_maxed_out:
                print("\nOnly max-retry functions remain. Exiting.")
                break

        remaining = len(unnamed_funcs)
        processed = total_functions - remaining
        progress = (float(processed) / float(total_functions)) * 100 if total_functions > 0 else 0

        eta_str = "calculating..."
        if function_times:
            avg_batch_time = sum(function_times) / len(function_times)
            batches_needed = float(remaining) / float(CONCURRENCY)
            eta_seconds = avg_batch_time * batches_needed
            eta_str = format_time(eta_seconds)

        elapsed = time.time() - start_time
        print("\n[{:.1f}%] Iteration {} | {}/{} remaining | Elapsed: {} | ETA: {}".format(
            progress, iteration, remaining, total_functions, format_time(elapsed), eta_str))

        batch = []
        batch_retry_counts = {}
        batch_start_time = time.time()

        retry_limit = max(1, CONCURRENCY / 2)
        retry_addresses = list(retry_queue.keys())

        for addr_str in retry_addresses:
            if len(batch) >= retry_limit:
                break

            func, decomp_code, decomp_results, retry_count = retry_queue[addr_str]

            if not func.getName().startswith("FUN_"):
                print("Removing {} from retry queue (already renamed)".format(addr_str))
                del retry_queue[addr_str]
                continue

            if retry_count >= MAX_RETRIES:
                print("Max retries exceeded for {} (giving up)".format(func.getName()))
                del retry_queue[addr_str]
                total_failed += 1
                continue

            print("Retry #{} for: {}".format(retry_count + 1, func.getName()))
            batch.append((func, decomp_code, decomp_results))
            batch_retry_counts[addr_str] = retry_count
            del retry_queue[addr_str]

        candidates = []
        for function in unnamed_funcs:
            addr_str = str(function.getEntryPoint())
            if addr_str in retry_queue:
                continue

            if calls_unnamed_functions(function):
                continue

            candidates.append(function)

        for function in candidates:
            if len(batch) >= CONCURRENCY:
                break

            func_name = function.getName()
            print("Decompiling: {} at {}".format(func_name, function.getEntryPoint()))

            decompiled_code, decompile_results = get_decompiled_code(function, decompiler)

            if not decompiled_code:
                print("  -> Could not decompile (skipping)")
                total_failed += 1
                continue

            batch.append((function, decompiled_code, decompile_results))

        if not batch and unnamed_funcs:
            print("\n" + "=" * 60)
            print("WARNING: Circular dependencies detected!")
            print("=" * 60)
            print("All remaining {} unnamed functions call other unnamed functions.".format(len(unnamed_funcs)))
            print("Attempting to break the cycle by force-processing some functions...")
            print("=" * 60)

            force_candidates = []
            for function in unnamed_funcs:
                addr_str = str(function.getEntryPoint())
                if addr_str in retry_queue:
                    continue

                try:
                    called_funcs = function.getCalledFunctions(monitor)
                    unnamed_call_count = 0
                    for cf in called_funcs:
                        if cf.getName().startswith("FUN_") and not cf.getEntryPoint().equals(function.getEntryPoint()):
                            unnamed_call_count += 1
                    force_candidates.append((function, unnamed_call_count))
                except:
                    pass

            force_candidates.sort(key=lambda x: x[1])
            force_batch_size = min(5, len(force_candidates))

            print("Force processing {} functions with fewest dependencies:".format(force_batch_size))
            for function, dep_count in force_candidates[:force_batch_size]:
                print("  {} (calls {} unnamed functions)".format(function.getName(), dep_count))

                decompiled_code, decompile_results = get_decompiled_code(function, decompiler)
                if decompiled_code:
                    batch.append((function, decompiled_code, decompile_results))
                else:
                    print("    -> Could not decompile")
                    total_failed += 1

            if not batch:
                print("\nCould not decompile any functions. Stopping.")
                break

        print("Processing batch of {} functions in parallel...".format(len(batch)))
        results, failed_items = process_batch(batch, CLAUDE_PATH)

        for func, decomp_code, decomp_results in failed_items:
            addr_str = str(func.getEntryPoint())

            if addr_str in batch_retry_counts:
                old_retry_count = batch_retry_counts[addr_str]
                new_retry_count = old_retry_count + 1
            else:
                new_retry_count = 1

            retry_queue[addr_str] = (func, decomp_code, decomp_results, new_retry_count)
            print("  -> Added {} to retry queue (attempt {}/{})".format(
                func.getName(), new_retry_count, MAX_RETRIES))

        for func, decomp_results, suggested_name, var_mappings, global_mappings in results:
            print("Applying results for: {}".format(func.getName()))

            if suggested_name:
                if rename_function(func, suggested_name):
                    total_renamed += 1
                    if var_mappings:
                        rename_variables(func, var_mappings, decomp_results)
                    if global_mappings:
                        rename_globals(program, global_mappings)

                    addr_str = str(func.getEntryPoint())
                    if addr_str in retry_queue:
                        del retry_queue[addr_str]
                        print("  -> Removed {} from retry queue (succeeded)".format(func.getName()))
            else:
                total_failed += 1
                addr_str = str(func.getEntryPoint())
                if addr_str in retry_queue:
                    del retry_queue[addr_str]

        if retry_queue:
            print("  -> Retry queue size: {}".format(len(retry_queue)))

        checkpoint_program(program, iteration)

        batch_time = time.time() - batch_start_time
        function_times.append(batch_time)
        if len(function_times) > 20:
            function_times.pop(0)

    total_time = time.time() - start_time
    print("\n" + "=" * 60)
    print("Renaming complete!")
    print("Successfully renamed: {}".format(total_renamed))
    print("Failed/Skipped: {}".format(total_failed))
    if retry_queue:
        print("Still in retry queue: {}".format(len(retry_queue)))
    print("Total time: {}".format(format_time(total_time)))
    print("=" * 60)

    decompiler.dispose()

if __name__ == "__main__":
    main()
```

## Configuration

Before running:

1. Set `CLAUDE_PATH` to your Claude Code CLI binary location
2. Set `CLAUDE_CODE_OAUTH_TOKEN` environment variable with your auth token
3. Adjust `CONCURRENCY` based on your rate limits (I used 60)
4. Optionally add domain-specific context to `PROMPT_SUFFIX` - or leave it empty if you're not sure what to add

The script will create periodic checkpoints so you don't lose progress if something crashes. Each checkpoint commits the transaction, making all renames permanent up to that point.

**Note**: This script has been tested with recent versions of Ghidra (specifically `11.4.2`), but Ghidra API changes can sometimes break scripts between major versions. If you hit errors, check your Ghidra version and adjust the script accordingly.

## Final Thoughts

This script won't replace actual reverse engineering expertise. But it transforms an unbearable slog into something manageable. When I'm jumping between functions trying to understand control flow, reading `computeSinCos()` vs `FUN_00fe0db4` is the difference between progress and pain.

Is it perfect? No. Does Claude sometimes hallucinate function names that sound plausible but are totally wrong? Yes. Would I use this again? Absolutely.

If you try this, I'd love to hear how it works for you. Especially if you find interesting failure modes or have ideas for improving the prompts. My RE experience is limited enough that I'm sure there are obvious improvements I'm missing.
