#!/usr/bin/env python3
"""
Generate test repositories of varying sizes for performance benchmarking.

Creates realistic directory structures with multiple programming languages.
"""

import argparse
import os
import random
from pathlib import Path

# Realistic code templates for different languages
PYTHON_TEMPLATE = '''#!/usr/bin/env python3
"""
Module: {module_name}
Generated for performance benchmarking.
"""

import os
import sys
import json
from typing import List, Dict, Optional

class {class_name}:
    """Business logic class for {module_name}."""

    def __init__(self, config: Dict[str, any]):
        self.config = config
        self.data = []

    def process(self, input_data: List[str]) -> Optional[Dict]:
        """Process input data according to configuration."""
        if not input_data:
            return None

        result = {{
            "status": "processed",
            "count": len(input_data),
            "timestamp": "2026-01-03"
        }}

        for item in input_data:
            self.data.append(self._transform(item))

        return result

    def _transform(self, item: str) -> Dict:
        """Transform a single item."""
        return {{
            "original": item,
            "processed": item.upper(),
            "length": len(item)
        }}

    def save_results(self, filepath: str):
        """Save results to file."""
        with open(filepath, 'w') as f:
            json.dump(self.data, f, indent=2)

def main():
    config = {{"mode": "production", "verbose": True}}
    processor = {class_name}(config)

    test_data = ["item1", "item2", "item3"]
    result = processor.process(test_data)

    print(f"Processed {{result['count']}} items")

if __name__ == "__main__":
    main()
'''

GO_TEMPLATE = '''package {package_name}

import (
\t"encoding/json"
\t"fmt"
\t"time"
)

// {struct_name} represents a business entity
type {struct_name} struct {{
\tID        string    `json:"id"`
\tName      string    `json:"name"`
\tCreatedAt time.Time `json:"created_at"`
\tData      map[string]interface{{}} `json:"data"`
}}

// New{struct_name} creates a new instance
func New{struct_name}(id, name string) *{struct_name} {{
\treturn &{struct_name}{{
\t\tID:        id,
\t\tName:      name,
\t\tCreatedAt: time.Now(),
\t\tData:      make(map[string]interface{{}}),
\t}}
}}

// Process handles business logic
func (e *{struct_name}) Process(input []byte) error {{
\tvar data map[string]interface{{}}
\tif err := json.Unmarshal(input, &data); err != nil {{
\t\treturn fmt.Errorf("failed to unmarshal: %w", err)
\t}}
\t
\te.Data = data
\treturn nil
}}

// ToJSON serializes the entity
func (e *{struct_name}) ToJSON() ([]byte, error) {{
\treturn json.Marshal(e)
}}

// Validate performs validation
func (e *{struct_name}) Validate() error {{
\tif e.ID == "" {{
\t\treturn fmt.Errorf("ID cannot be empty")
\t}}
\tif e.Name == "" {{
\t\treturn fmt.Errorf("Name cannot be empty")
\t}}
\treturn nil
}}
'''

JAVASCRIPT_TEMPLATE = '''/**
 * Module: {module_name}
 * Generated for performance benchmarking
 */

const fs = require('fs');
const path = require('path');

class {class_name} {{
  constructor(options = {{}}) {{
    this.options = {{
      verbose: false,
      timeout: 5000,
      retries: 3,
      ...options
    }};
    this.data = [];
    this.errors = [];
  }}

  async process(items) {{
    if (!Array.isArray(items)) {{
      throw new TypeError('Items must be an array');
    }}

    for (const item of items) {{
      try {{
        const result = await this.processItem(item);
        this.data.push(result);
      }} catch (error) {{
        this.errors.push({{
          item,
          error: error.message,
          timestamp: new Date().toISOString()
        }});
      }}
    }}

    return {{
      processed: this.data.length,
      errors: this.errors.length,
      data: this.data
    }};
  }}

  async processItem(item) {{
    return new Promise((resolve) => {{
      setTimeout(() => {{
        resolve({{
          original: item,
          processed: String(item).toUpperCase(),
          timestamp: Date.now()
        }});
      }}, 10);
    }});
  }}

  saveResults(filepath) {{
    const results = {{
      data: this.data,
      errors: this.errors,
      metadata: {{
        total: this.data.length,
        failed: this.errors.length,
        timestamp: new Date().toISOString()
      }}
    }};

    fs.writeFileSync(filepath, JSON.stringify(results, null, 2));
  }}

  reset() {{
    this.data = [];
    this.errors = [];
  }}
}}

module.exports = {{ {class_name} }};
'''

JAVA_TEMPLATE = '''package {package_name};

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * {class_name} - Business logic component
 * Generated for performance benchmarking
 */
public class {class_name} {{

    private final Map<String, Object> config;
    private final List<Map<String, Object>> data;
    private final ObjectMapper objectMapper;

    public {class_name}(Map<String, Object> config) {{
        this.config = config != null ? config : new HashMap<>();
        this.data = new ArrayList<>();
        this.objectMapper = new ObjectMapper();
    }}

    public Map<String, Object> process(List<String> items) {{
        if (items == null || items.isEmpty()) {{
            return createErrorResponse("No items to process");
        }}

        Map<String, Object> result = new HashMap<>();
        result.put("status", "success");
        result.put("count", items.size());

        for (String item : items) {{
            Map<String, Object> processed = processItem(item);
            data.add(processed);
        }}

        result.put("data", data);
        return result;
    }}

    private Map<String, Object> processItem(String item) {{
        Map<String, Object> result = new HashMap<>();
        result.put("original", item);
        result.put("processed", item.toUpperCase());
        result.put("length", item.length());
        result.put("timestamp", System.currentTimeMillis());
        return result;
    }}

    private Map<String, Object> createErrorResponse(String message) {{
        Map<String, Object> error = new HashMap<>();
        error.put("status", "error");
        error.put("message", message);
        return error;
    }}

    public void saveResults(String filepath) throws Exception {{
        objectMapper.writerWithDefaultPrettyPrinter()
                   .writeValue(new java.io.File(filepath), data);
    }}
}}
'''

class TestRepoGenerator:
    """Generate test repositories with realistic code structures."""

    def __init__(self, base_dir: Path, target_files: int):
        self.base_dir = Path(base_dir)
        self.target_files = target_files
        self.generated_files = 0

    def generate(self):
        """Generate the test repository."""
        print(f"Generating test repository: {self.target_files} files")
        print(f"Output directory: {self.base_dir}")

        self.base_dir.mkdir(parents=True, exist_ok=True)

        # Calculate distribution
        files_per_lang = self.target_files // 4

        # Generate Python files
        self._generate_python_files(files_per_lang)

        # Generate Go files
        self._generate_go_files(files_per_lang)

        # Generate JavaScript files
        self._generate_javascript_files(files_per_lang)

        # Generate Java files
        self._generate_java_files(files_per_lang)

        # Generate config files
        self._generate_config_files()

        # Generate README
        self._generate_readme()

        print(f"Generated {self.generated_files} files")

    def _generate_python_files(self, count: int):
        """Generate Python source files."""
        py_dir = self.base_dir / "python" / "src"
        py_dir.mkdir(parents=True, exist_ok=True)

        modules = []
        for i in range(count):
            module_name = f"module_{i:04d}"
            class_name = f"Processor{i:04d}"

            content = PYTHON_TEMPLATE.format(
                module_name=module_name,
                class_name=class_name
            )

            filepath = py_dir / f"{module_name}.py"
            filepath.write_text(content)
            modules.append(module_name)
            self.generated_files += 1

            if i % 100 == 0:
                print(f"  Python: {i}/{count} files")

        # Create __init__.py
        init_content = "\n".join(f"from .{m} import *" for m in modules[:50])  # First 50 only
        (py_dir / "__init__.py").write_text(init_content)
        self.generated_files += 1

    def _generate_go_files(self, count: int):
        """Generate Go source files."""
        go_dir = self.base_dir / "go" / "pkg"
        go_dir.mkdir(parents=True, exist_ok=True)

        for i in range(count):
            package_name = f"package{i:04d}"
            struct_name = f"Entity{i:04d}"

            content = GO_TEMPLATE.format(
                package_name=package_name,
                struct_name=struct_name
            )

            pkg_dir = go_dir / package_name
            pkg_dir.mkdir(exist_ok=True)

            filepath = pkg_dir / f"{package_name}.go"
            filepath.write_text(content)
            self.generated_files += 1

            if i % 100 == 0:
                print(f"  Go: {i}/{count} files")

        # Create go.mod
        gomod = f"""module github.com/test/benchmark

go 1.21
"""
        (self.base_dir / "go" / "go.mod").write_text(gomod)
        self.generated_files += 1

    def _generate_javascript_files(self, count: int):
        """Generate JavaScript source files."""
        js_dir = self.base_dir / "javascript" / "src"
        js_dir.mkdir(parents=True, exist_ok=True)

        for i in range(count):
            module_name = f"module{i:04d}"
            class_name = f"Processor{i:04d}"

            content = JAVASCRIPT_TEMPLATE.format(
                module_name=module_name,
                class_name=class_name
            )

            filepath = js_dir / f"{module_name}.js"
            filepath.write_text(content)
            self.generated_files += 1

            if i % 100 == 0:
                print(f"  JavaScript: {i}/{count} files")

        # Create package.json
        package_json = {
            "name": "benchmark-test",
            "version": "1.0.0",
            "description": "Performance benchmark test repository",
            "main": "index.js",
            "scripts": {
                "test": "echo \"No tests\""
            }
        }

        import json
        (self.base_dir / "javascript" / "package.json").write_text(
            json.dumps(package_json, indent=2)
        )
        self.generated_files += 1

    def _generate_java_files(self, count: int):
        """Generate Java source files."""
        java_dir = self.base_dir / "java" / "src" / "main" / "java" / "com" / "test"
        java_dir.mkdir(parents=True, exist_ok=True)

        for i in range(count):
            package_name = "com.test"
            class_name = f"Processor{i:04d}"

            content = JAVA_TEMPLATE.format(
                package_name=package_name,
                class_name=class_name
            )

            filepath = java_dir / f"{class_name}.java"
            filepath.write_text(content)
            self.generated_files += 1

            if i % 100 == 0:
                print(f"  Java: {i}/{count} files")

    def _generate_config_files(self):
        """Generate configuration files."""
        # .gitignore
        gitignore = """*.pyc
__pycache__/
*.class
node_modules/
.DS_Store
"""
        (self.base_dir / ".gitignore").write_text(gitignore)
        self.generated_files += 1

        # Makefile
        makefile = """all:
\t@echo "Test repository for benchmarking"

clean:
\tfind . -name "*.pyc" -delete
\tfind . -name "__pycache__" -delete
"""
        (self.base_dir / "Makefile").write_text(makefile)
        self.generated_files += 1

    def _generate_readme(self):
        """Generate README file."""
        readme = f"""# Performance Benchmark Test Repository

This repository was auto-generated for SCA performance benchmarking.

## Statistics

- **Total files**: {self.generated_files}
- **Target size**: {self.target_files} files
- **Languages**: Python, Go, JavaScript, Java

## Structure

```
/python         - Python source files
/go             - Go packages
/javascript     - JavaScript modules
/java           - Java classes
```

## Purpose

Used to measure SCA audit performance on repositories of varying sizes.

Generated: 2026-01-03
"""
        (self.base_dir / "README.md").write_text(readme)
        self.generated_files += 1

def main():
    parser = argparse.ArgumentParser(description="Generate test repositories for performance benchmarking")
    parser.add_argument("--size", type=str, required=True,
                       choices=["small", "medium", "large", "xlarge"],
                       help="Repository size: small(1K), medium(10K), large(50K), xlarge(100K)")
    parser.add_argument("--output", type=str, required=True,
                       help="Output directory path")

    args = parser.parse_args()

    # Map size to file count
    size_map = {
        "small": 1000,
        "medium": 10000,
        "large": 50000,
        "xlarge": 100000
    }

    target_files = size_map[args.size]
    output_dir = Path(args.output)

    generator = TestRepoGenerator(output_dir, target_files)
    generator.generate()

    print(f"\n✅ Test repository generated successfully")
    print(f"   Size: {args.size} ({target_files} files)")
    print(f"   Location: {output_dir.absolute()}")

if __name__ == "__main__":
    main()
