import re
import sys
import textwrap
import importlib.metadata

import markdown
from bs4 import BeautifulSoup, Comment
from pygments.formatters import HtmlFormatter


def bootstrapify_html(html_string: str) -> str:
    """
    Modifies an HTML string to apply Bootstrap 5 classes and structure.
    """
    soup = BeautifulSoup(html_string, "lxml")

    # Create a new body and a container div to wrap the content
    body = soup.find("body")
    if not body:
        # If no body tag, work with the top-level elements
        body = soup

    container = soup.new_tag("div", attrs={"class": "container py-4"})

    # Move all original content into the container
    original_content = body.find_all(recursive=False)
    for element in original_content:
        container.append(element.extract())
    body.append(container)

    # Style the button to be big and blue
    button = soup.find("a")
    if button:
        button["class"] = "btn btn-primary btn-lg"
        button["type"] = "button"
        # For better presentation, wrap it in a centered grid div
        button_wrapper = soup.new_tag(
            "div", attrs={"class": "d-grid gap-2 col-6 mx-auto my-4"}
        )
        button.wrap(button_wrapper)

    # Style headings for better spacing and typography
    h1 = soup.find("h1")
    if h1:
        h1["class"] = "display-5"

    for h2 in soup.find_all("h2"):
        h2["class"] = "mt-5"
        h2["id"] = h2.get_text(strip=True).lower().replace(" ", "-")

    for h3 in soup.find_all("h3"):
        h3["id"] = h3.get_text(strip=True).lower().replace(" ", "-")

    for h4 in soup.find_all("h4"):
        h4["class"] = "mt-4"

    # Responsive width images
    for img in soup.find_all("img"):
        img["class"] = "img-fluid"

    # Remove err class incorrectly added to some stuff
    for span in soup.find_all("span", class_="err"):
        span["class"].remove("err")

    # Style code blocks
    for div in soup.find_all("div", class_="codehilite"):
        pre_tag = div.find("pre")
        if pre_tag:
            pre_tag["class"] = "codehilite bg-light p-3 rounded-3"
        div.unwrap()  # Remove the outer div, keeping the styled <pre>

    # Convert any remaining blockquotes
    for bq in soup.find_all("blockquote"):
        # Check if it's already part of a figure to avoid processing twice
        if bq.find_parent("figure"):
            continue

        caption_text = bq.get_text(strip=True)
        figure = soup.new_tag("figure", attrs={"class": "text-center my-4"})
        figcaption = soup.new_tag("figcaption", attrs={"class": "figure-caption mt-2"})
        figcaption.string = caption_text
        figure.append(figcaption)
        bq.replace_with(figure)

    # Parse the HTML document
    soup = BeautifulSoup(soup.prettify(), "html.parser")

    # Create a new <link> tag object
    new_link_tag = soup.new_tag(
        "link",
        href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css",
        rel="stylesheet",
        integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB",
        crossorigin="anonymous",
    )
    new_script_tag_mermaidjs = soup.new_tag(
        "script",
        type="module",
        src="https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs",
        # rel="stylesheet",
        # integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB",
        crossorigin="anonymous",
    )

    # Append the new tags to the end of the <head>
    soup.head.append(new_link_tag)
    soup.head.append(new_script_tag_mermaidjs)

    return soup.prettify()


def add_consent_button(html_text: str, authorize_url: str) -> str:
    find = "<p>Open Sourced Proof of Concept</p>"
    replace = "<br/><center><p style='color: red;'><strong>This acts as a proxy! All data you would usually send to the DigitalOcean API instead is configured to be sent to this service!!</strong></p></center>"
    replace += f"\n<a href=\"{authorize_url}\" >Confirm Consent and Authorize</a>"
    html_text = html_text.replace(find, replace)

    find = "<!-- BLUESKY_LOGIN -->"
    replace = textwrap.dedent(
        """
        <form action="/login" method="post" class="login-form">
          <div class="container text-center">
            <div class="row">
              <div class="col-8">
                <input type="atproto-handle" class="form-control" id="inputATProtoHandle" aria-describedby="atprotoHandleHelp" name="handle" placeholder="Enter your handle (eg alice.bsky.social)" >
                <div id="atprotoHandleHelp" class="form-text">Don't have an account on the Atmosphere? <a href="https://bsky.app">Sign up for Bluesky</a> to create one now!</div>
              </div>
              <button type="submit" class="col btn btn-primary" >Log in</button>
            </div>
          </div>
        </form>
        """
    )
    html_text = html_text.replace(find, replace)

    find = "<!-- BLUESKY_POLICY_TOKEN -->"
    replace = textwrap.dedent(
        """
        <iframe src="/policy-token" class="container py-4">
        </iframe>
        """
    )
    html_text = html_text.replace(find, replace)
    return html_text


def set_this_endpoint(readme_markdown: str, this_endpoint: str) -> str:
    find = "https://<deployment-name>.ondigitalocean.app"
    replace = this_endpoint
    return readme_markdown.replace(find, replace)


def replace_mermaid_blocks(text: str) -> str:
    """
    Finds ```mermaid blocks and replaces them with
    <pre class="mermaid">...</pre> tags using regular expressions.
    """
    # This pattern looks for:
    # ^```mermaid$   - A line that is exactly "```mermaid"
    # (.*?)         - A non-greedy capture of any characters (including newlines)
    # ^```$         - A line that is exactly "```"
    #
    # Flags:
    # re.DOTALL (or re.S) allows '.' to match newlines.
    # re.MULTILINE (or re.M) allows '^' and '$' to match the start/end of lines.
    pattern = re.compile(r'^```mermaid\n(.*?)\n^```$', re.DOTALL | re.MULTILINE)

    # The replacement string:
    # \1 is a backreference to the first captured group (the content inside the block).
    replacement = r'<pre class="mermaid">\1</pre>'

    return pattern.sub(replacement, text)


def get_readme_markdown(package_name: str) -> str:
    markdown_string = importlib.metadata.metadata(__package__)["Description"]

    markdown_string = replace_mermaid_blocks(markdown_string)

    return markdown_string


def convert_readme_to_html(readme_markdown: str) -> str:
    html_content = markdown.markdown(
        readme_markdown,
        extensions=["fenced_code", "codehilite"],
    )

    formatter = HtmlFormatter(style="default", full=True, cssclass="codehilite")
    css_styles = formatter.get_style_defs(".codehilite")

    return f"<style>{css_styles}</style>\n{html_content}"


if __name__ == "__main__":
    print(bootstrapify_html(add_consent_button(get_readme_as_html(__package__), sys.argv[-1])))
