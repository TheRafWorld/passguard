from drafter import *
from dataclasses import dataclass

set_website_title("PassGuard")
set_site_information(
    author = "Rafael Gibrial",
    description = "",
    sources = "",
    planning = "",
    links = ""
)
set_website_favicon("")
set_page_transition("fade")
set_page_transition("black", 0.3)

@dataclass
class PasswordRecord:
    masked_password: str
    score: int
    rating_label: str

@dataclass
class State:
    current_password: str
    history: list[PasswordRecord]
    strict_mode: bool
    active_category: int

#These are helper styling funcitions
def styled_page_container(*contents) -> PageContent:
    """
    Returns a styled page layout using a Div container.
    Accepts any number of child components (*contents).
    """
    return Div(
        *contents,
        style_display = "flex",
        style_flex_direction = "column",
        style_align_items = "center",
        style_padding = "2rem",
        style_border = "2px solid black",
        style_border_radius = "8px",
        style_margin = "8px",
        style_text_align = "center"
    )

@route("/")
def index(state: State) -> Page:
    """
    Home page route displaying the welcome hub and navigation links.
    """
    # Call our container helper and pass all page elements into it
    home_content = styled_page_container(
        Header("Welcome to PassGuard", 1),
        Paragraph("An interactive security tool to evaluate credential strength, test complexity rules, and maintain audit logs."),
        Row(
            Button("Start Analyzing", analyzer),
            Button("Learn Security Tips", analyzer)
        )
    )
    
    return Page(state, [
        home_content
    ])

@route("/analyzer")
def analyzer(state: State) -> Page:
    """
    Analyzer page containing the required inputs (TextBox, CheckBox, SelectBox).
    This is where the user will input there password for analyzation.
    """
    return Page(state, [
        "Password Analyzer",
        TextBox("current_password", label="Enter Password"),
        CheckBox("strict_mode", label="Enforce Strict Mode (Symbols Required)"),
        SelectBox("active_category", ["Personal", "Corporate", "Government"], label="Security Standard"),
        Button("Back to Home", index)
    ])

@route("tips")
def tips(state: State) -> Page:
    """
    Tips page containing the required inputs (TextBox, CheckBox, SelectBox).
    """
    pass

start_server(open_browser=False)
