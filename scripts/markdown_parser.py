import re
from collections import OrderedDict

def extract_code_from_markdown(markdown_text: str) -> OrderedDict:
    """
    Parses a markdown string to extract code blocks and their intended destinations.

    The function identifies H4 headers and fenced code blocks. If a code block
    is immediately preceded by an H4 header, the header's content is treated as
    the filepath for the code block. If a code block has no preceding H4 header,
    it is treated as a shell command, and its key in the returned dictionary
    is the first line of the code block itself.

    Args:
        markdown_text: A string containing the markdown to be parsed.

    Returns:
        An OrderedDict where keys are either filepaths (from H4 headers) or
        the first line of shell commands, and values are the corresponding
        multiline code/content strings. The order reflects the appearance
        in the source markdown.
        
    Example:
        markdown = '''
        #### hello.py
        ```python
        print("Hello, World!")
        ```

        ```bash
        python hello.py
        ```
        '''
        result = extract_code_from_markdown(markdown)
        # result would be:
        # OrderedDict([
        #     ('hello.py', 'print("Hello, World!")\n'),
        #     ('python hello.py', 'python hello.py\n')
        # ])
    """
    # This regex pattern uses a non-capturing group to find either an H4 header
    # or a fenced code block. It captures the relevant parts of each match.
    # - `^####\s*(?P<filepath>.+?)\s*$`: Matches a line starting with '####',
    #   capturing the rest of the line as 'filepath'.
    # - `^```(?P<lang>[\w\+\-\.]*)\n(?P<code>[\s\S]+?)\n```$`: Matches a fenced
    #   code block, capturing the language specifier and the code content.
    pattern = re.compile(
        r"^(?:####\s*(?P<filepath>.+?)\s*$)|(?:^```(?P<lang>[\w\+\-\.]*)\n(?P<code>[\s\S]+?)\n^```$)",
        re.MULTILINE
    )

    results = []
    last_filepath = None

    for match in pattern.finditer(markdown_text):
        # Check if the 'filepath' group was captured (i.e., we found an H4)
        if match.group("filepath"):
            last_filepath = match.group("filepath").strip()
        # Check if the 'code' group was captured (i.e., we found a code block)
        elif match.group("code") is not None:
            code_content = match.group("code")

            if match.group("lang") == "mermaid":
                continue
            
            if last_filepath:
                # A filepath was set by a preceding H4, so use it as the key
                results.append([last_filepath, code_content])
                # results[last_filepath] = code_content
                last_filepath = None  # Reset the filepath after use
            else:
                # No preceding H4, treat as a command. Use the first line as the key.
                if code_content.strip():
                    first_line = code_content.strip().split('\n', 1)[0]
                    # results[first_line] = code_content
                    results.append([first_line, code_content])
    
    return results


def main():
    import sys
    markdown_sample = sys.stdin.read()

    extracted_data = extract_code_from_markdown(markdown_sample)

    import json
    print(json.dumps(extracted_data, indent=2))


if __name__ == '__main__':
    main()
