from dataclasses import dataclass, field
from drafter import *

"""
PassGuard: An Interactive Password Strength Analyzer
Author: Rafael Gibrial
This application evaluates password strength based on length, character variety, and category-specific rules. 
It maintains an audit log of previous evaluations and provides actionable feedback to users.
"""

"""
ADVANCED TECHNIQUE DOCUMENTATION:
1. Dataclass Factory Initialization: Utilizing `field(default_factory=list)` 
ensures mutable default objects (lists) are safely instantiated per session state.
2. Variadic Argument Unpacking: Using `*contents` in helper functions to 
accept an arbitrary number of positional component arguments dynamically.
3. Type-Hinted Complex Structures: Utilizing nested generic type hints 
(`tuple[int, str, list[tuple[str, bool]]]`) for strict type safety.
"""
set_website_style("yorha")
set_website_title("PassGuard")
set_site_information(
    author = "Rafael Gibrial",
    description = "An interactive security tool to evaluate credential strength and maintain audit logs.",
    sources = "CICS106 Course Materials",
    planning = ["CS1 Final Project 0_ Pick a Problem.docx", "CS1 Final Project 1_ Design.docx"],
    links = "https://drafter-edu.github.io/drafter/reference/index.html"
)
set_website_favicon("")
set_page_transition("fade")
set_page_transition("black", 0.3)

@dataclass
class PasswordRecord:
    """
        A single record of a password evaluation, including the masked password, 
        score, rating label, and rule checks.
        
        Attributes:
            masked_password (str): The latest saved password in a partially obscured format.
            score (int): The latest saved password score.
            rating_label (str): The rating label for the latest password.
            checks (list[tuple[str, bool]]): A list of rule checks and their results.
    """
    masked_password: str
    score: int
    rating_label: str

    # Advanced type hinting for a list of tuples containing rule descriptions and boolean results
    # plus the use of `field(default_factory=list)` to ensure each instance has its own list
    checks: list[tuple[str, bool]] = field(default_factory=list)

@dataclass
class State:
    """
    The current state of the PassGuard application.
    
    Attributes:
        current_password (str): The latest password input by the user.
        history (list[PasswordRecord]): A list of previous password evaluations.
        is_strict (bool): Indicates whether strict mode is enabled.
        active_category (str): The currently selected password category.
    """
    current_password: str = ""
    history: list[PasswordRecord] = field(default_factory=list)
    is_strict: bool = False
    active_category: str = "Personal"

# ==========================================
# FUNCTIONS
# ==========================================

# Helper function to create a styled page container with consistent layout and 
# design properties utilizing variadic unpacking (*contents)
# *contents allows for any number of child components to be passed in, enabling flexible layout composition.
def styled_page_container(*contents) -> PageContent:
    """
    This function creates a styled container for page content, 
    applying consistent layout and design properties. It uses variadic unpacking 
    to accept any number of child components.
    
    Args:
        contents: Any number of child components to include in the container.
    Returns:
        PageContent: A styled Div container with the specified contents.
    """
    return Div(
        *contents,
        style_display = "flex",
        style_flex_direction = "column",
        style_align_items = "center",
        style_width="100%",
        style_padding = "2rem",
        style_border = "2px solid black",
        style_border_radius = "8px",
        style_margin = "8px",
        style_text_align = "center"
    )

# Decomposed helper functions for password evaluation logic
# Each evaluation aspect (length, variety, modifiers) is handled in its own function, 
# returning both score and checks for modularity and testability.

# This function evaluates the password length and returns a score and a list of checks.
def evaluate_length_rules(password: str) -> tuple[int, list[tuple[str, bool]]]:
    """
        This function evaluates the password length and returns a score and 
        a list of checks that evaluated to True for the password.
        
        Args:
            password (str): The password to evaluate.
        Returns:
            tuple[int, list[tuple[str, bool]]]: Score and list of checks for length rules.
    """
    score = 0
    checks = []

    if len(password) >= 8:
        checks.append(("Length: 8+ characters", True))
    else:
        checks.append(("Length: 8+ characters", False))

    if len(password) >= 12:
        checks.append(("Length: 12+ characters (+40 pts)", True))
    else:
        checks.append(("Length: 12+ characters (+40 pts)", False))

    if len(password) < 8:
        score += 10
    elif len(password) < 12:
        score += 40
    else:
        score += 60
        
    return score, checks

def evaluate_variety_rules(password: str) -> tuple[int, list[tuple[str, bool]]]:
    """
            This function evaluates the password variety and returns a score and 
            a list of checks that evaluated to True for the password.
            
            Args:
                password (str): The password to evaluate.
            Returns:
                tuple[int, list[tuple[str, bool]]]: Score and list of checks for variety rules.
    """
    score = 0
    checks = []

    has_upper = False
    for char in password:
        if char.isupper():
            has_upper = True
            break
    
    has_lower = False
    for char in password:
        if char.islower():
            has_lower = True
            break

    has_digit = False
    for char in password:
        if char.isdigit():
            has_digit = True
            break

    checks.append(("Contains uppercase & lowercase letters", has_upper and has_lower))
    if has_upper and has_lower:
        score += 15

    checks.append(("Contains numbers", has_digit))
    if has_digit:
        score += 15
        
    return score, checks

def evaluate_modifiers(password: str, is_strict: bool, category: str) -> tuple[int, list[tuple[str, bool]]]:
    """
            Helper function to apply strict mode and category-specific rules.
            
            Args:
                password (str): The password to evaluate.
                is_strict (bool): Indicates whether strict mode is enabled.
                category (str): The category of the password.
            Returns:
                tuple[int, list[tuple[str, bool]]]: Score modifier and list of checks for modifier rules.
        """
    score_modifier = 0
    checks = []

    has_symbol = False
    for char in password:

        # .isalnum() returns True if the character is alphanumeric (letters or digits),
        # so we check for non-alphanumeric characters to identify symbols.
        if not char.isalnum():
            has_symbol = True
            break

    if is_strict:
        checks.append(("Strict Mode: Contains symbols", has_symbol))
        if has_symbol:
            score_modifier += 10
        else:
            score_modifier -= 15

    if category == "Personal":
        personal_pass = len(password) >= 10 and has_symbol
        checks.append(("Personal Standard: 10+ characters & symbols", personal_pass))
        if not personal_pass:
            score_modifier -= 10

    if category == "Corporate":
        corp_pass = len(password) >= 12 and has_symbol
        checks.append(("Corporate Standard: 12+ characters & symbols", corp_pass))
        if not corp_pass:
            score_modifier -= 15

    if category == "Government":
        gov_pass = len(password) >= 14
        checks.append(("Government Standard: 14+ characters", gov_pass))
        if not gov_pass:
            score_modifier -= 20

    return score_modifier, checks

def evaluate_password(password: str, is_strict: bool, category: str) -> tuple[int, str, list[tuple[str, bool]]]:
    """
        This main evaluation function coordinates helper decomposition to 
        compute the final password score, rating label, and rule checks.
        
        Args:
            password (str): The password to evaluate.
            is_strict (bool): Indicates whether strict mode is enabled.
            category (str): The category of the password.
        Returns:
            tuple[int, str, list[tuple[str, bool]]]: Score, rating label, and checks.
    """
    if not password:
        return 0, "Empty", []

    # Decomposed modular function calls
    len_score, len_checks = evaluate_length_rules(password)
    var_score, var_checks = evaluate_variety_rules(password)
    mod_score, mod_checks = evaluate_modifiers(password, is_strict, category)

    # Aggregate scores and checks from all evaluation aspects
    total_score = max(0, min(100, len_score + var_score + mod_score))
    all_checks = len_checks + var_checks + mod_checks

    # Determine rating label based on total score using a clear threshold system
    if (total_score >= 80):
        label = "Very Strong"
    elif total_score >= 60:
        label = "Strong"
    elif total_score >= 40:
        label = "Fair"
    elif total_score >= 20:
        label = "Weak"
    else:
        label = "Very Weak"

    return total_score, label, all_checks

def mask_password(password: str) -> str:
    """
        This function returns a partially obscured version of the password.
        
        Args:
            password (str): The password to obscure.
        Returns:
            str: The masked password.
    """
    if len(password) <= 4:
        return "****"
    return password[:4] + "*" * (len(password) - 4)

# ==========================================
# ROUTES
# ==========================================

# Route 1: Action route for submitting password analysis
@route
def submit_analysis(state: State, current_password: str, is_strict: bool, active_category: str) -> Page:
    """Action triggered when evaluating the password using state binding."""
    score, label, checks = evaluate_password(current_password, is_strict, active_category)
    masked = mask_password(current_password)

    # Each password evaluation is recorded in the history with a PasswordRecord dataclass instance.
    record = PasswordRecord(masked_password = masked, score = score, rating_label = label, checks = checks)
    state.history.append(record)
    
    return results(state)

# Route 2: Home page
@route("/")
def index(state: State) -> Page:
    """Home page route displaying the welcome hub and navigation links."""
    home_content = styled_page_container(
        Header("Welcome to PassGuard", 1),
        Paragraph("An interactive security tool to evaluate credential strength, test complexity rules, and maintain audit logs."),
        Row(
            Button("Start Analyzing", analyzer),
            Button("Security Tips", tips),
            Button("About PassGuard", about)
        )
    )
    
    return Page(state, [home_content])

# Route 3: Analyzer page
@route("/analyzer")
def analyzer(state: State) -> Page:
    """Analyzer page containing input fields (TextBox, CheckBox, SelectBox)."""
    analyzer_content = styled_page_container(
        Header("Password Analyzer", 2),
        Span(
            "Enter your password below to evaluate its strength based on length, character variety, and category-specific rules.",
            LineBreak(),
            TextBox("current_password", label="Enter Password"),
            LineBreak(),
            CheckBox("is_strict", label="Enforce Strict Mode"),
            "Enable strict mode to require symbols in your password, which may affect the score.",
            LineBreak(),
            "Choose a security standard below to evaluate your password against category-specific rules.",
            LineBreak(),
            SelectBox("active_category", ["Personal", "Corporate", "Government"], label="Security Standard"),
        ),
        Button("Analyze Strength", submit_analysis),
        LineBreak(),
        Button("Back to Home", index)
    )
    
    return Page(state, [analyzer_content])

# Route 4: Results page
@route("/results")
def results(state: State) -> Page:
    """Results page displaying the evaluation breakdown with checkmarks/crosses."""
    latest = state.history[-1] if state.history else PasswordRecord("****", 0, "No Analysis", [])
    
    # Prepare a display list of checks with visual indicators (checkmarks and crosses) for user-friendly feedback.
    check_display_list = []
    for rule, passed in latest.checks:
        if passed:
            check_display_list.append("✅ " + rule)
        else:
            check_display_list.append("❌ " + rule)
    
    results_content = styled_page_container(
        Header("Results", 2),
        Header(f"Score: {latest.score} / 100 ({latest.rating_label})", 3),
        Paragraph(f"Evaluated Password: {latest.masked_password}"),
        Header("Condition Breakdown", 4),
        BulletedList(check_display_list) if check_display_list else Paragraph("No checks available."),
        LineBreak(),
        Row(
            Button("Test Another", analyzer),
            Button("View Past Passwords", history),
            Button("Back to Home", index)
        )
    )
    
    return Page(state, [results_content])

# Route 5: History page
@route("/history")
def history(state: State) -> Page:
    """History audit log page."""
    
    history_items = []
    for rec in state.history:
        masked = rec.masked_password
        score = rec.score
        label = rec.rating_label
        
        item = "Password: " + masked + " | Score: " + str(score) + " (" + label + ")"
        history_items.append(item)

    history_content = styled_page_container(
        Header("Audit History", 2),
        BulletedList(history_items) if history_items else Paragraph("No history recorded yet."),
        LineBreak(),
        Button("Return Home", index)
    )
    
    return Page(state, [history_content])

# Route 6: Tips page
@route("/tips")
def tips(state: State) -> Page:
    """Tips page providing security guidelines."""
    tips_content = styled_page_container(
        Header("Security Tips", 2),
        Paragraph("1. Use passphrases combining 4+ random words."),
        Paragraph("2. Avoid reusing passwords across critical services."),
        LineBreak(),
        Button("Back to Home", index)
    )
    return Page(state, [tips_content])

# Route 7: About page
@route("/about")
def about(state: State) -> Page:
    """About page explaining the application architecture and purpose."""
    about_content = styled_page_container(
        Header("About PassGuard", 2),
        Paragraph("PassGuard This application evaluates password strength based on length, character variety, "
        "and category-specific rules. It maintains an audit log of previous evaluations and " \
        "provides actionable feedback to users."),
        LineBreak(),
        Button("Back to Home", index)
    )
    return Page(state, [about_content])

# ==========================================
# UNIT TESTS
# ==========================================

# Unit test for the styled_page_container function
assert_equal(
    styled_page_container(Header("Test Header", 1), Paragraph("Test Paragraph")),
    Div(
        Header("Test Header", 1),
        Paragraph("Test Paragraph"),
        style_display = "flex",
        style_flex_direction = "column",
        style_align_items = "center",
        style_width="100%",
        style_padding = "2rem",
        style_border = "2px solid black",
        style_border_radius = "8px",
        style_margin = "8px",
        style_text_align = "center"
    )
)   

# Unit test for the evaluate_password function with a sample password
assert_equal(
    evaluate_password("Secret123!", False, "Personal"),
    (
        70,
        "Strong",
        [
            ("Length: 8+ characters", True),
            ("Length: 12+ characters (+40 pts)", False),
            ("Contains uppercase & lowercase letters", True),
            ("Contains numbers", True),
            ("Personal Standard: 10+ characters & symbols", True)
        ]
    )
)

# Unit test for the mask_password function with a sample password
assert_equal(
    mask_password("Secret123!"),
    "Secr******"
)

# Unit test for the submit_analysis route with a sample password and state
assert_equal(
    submit_analysis(State(), "Secret123!", False, "Personal"),
    Page(
        State(
            current_password="",
            history=[PasswordRecord("Secr******", 70, "Strong", [
                ("Length: 8+ characters", True),
                ("Length: 12+ characters (+40 pts)", False),
                ("Contains uppercase & lowercase letters", True),
                ("Contains numbers", True),
                ("Personal Standard: 10+ characters & symbols", True)
            ])],
            is_strict = False,
            active_category = "Personal"
        ),
        [
            styled_page_container(
                Header("Results", 2),
                Header("Score: 70 / 100 (Strong)", 3),
                Paragraph("Evaluated Password: Secr******"),
                Header("Condition Breakdown", 4),
                BulletedList([
                    "✅ Length: 8+ characters",
                    "❌ Length: 12+ characters (+40 pts)",
                    "✅ Contains uppercase & lowercase letters",
                    "✅ Contains numbers"
                ]),
                LineBreak(),
                Row(
                    Button("Test Another", analyzer),
                    Button("View Past Passwords", history),
                    Button("Back to Home", index),
                ),
            )
        ],
    ),
)

# Unit test for the index route to ensure correct page rendering and state management
assert_equal(
    index(State()),
    Page(
        State(
            current_password="",
            history=[],
            is_strict=False,
            active_category="Personal"
        ),
        [
            styled_page_container(
                Header("Welcome to PassGuard", 1),
                Paragraph(
                    "An interactive security tool to evaluate credential strength, "
                    "test complexity rules, and maintain audit logs."
                ),
                Row(
                    Button("Start Analyzing", analyzer),
                    Button("Security Tips", tips),
                    Button("About PassGuard", about),
                ),
            )
        ],
    ),
)

# Unit test for the analyzer route to ensure correct page rendering and state management
assert_equal(
    analyzer(State()),
    Page(
        State(
            current_password="",
            history=[],
            is_strict=False,
            active_category="Personal",
        ),
        [
            styled_page_container(
                Header("Password Analyzer", 2),
                Span(
                    "Enter your password below to evaluate its strength based on length, character variety, and category-specific rules.",
                    LineBreak(),
                    TextBox("current_password", label="Enter Password"),
                    LineBreak(),
                    CheckBox("is_strict", label="Enforce Strict Mode"),
                    "Enable strict mode to require symbols in your password, which may affect the score.",
                    LineBreak(),
                    "Choose a security standard below to evaluate your password against category-specific rules.",
                    LineBreak(),
                    SelectBox("active_category", ["Personal", "Corporate", "Government"], label="Security Standard"),
                ),
                Button("Analyze Strength", submit_analysis),
                LineBreak(),
                Button("Back to Home", index),
            )
        ],
    ),
)

# Unit test for the results route to ensure correct page rendering and state management
assert_equal(
    results(State(history=[PasswordRecord("Secr******", 70, "Strong", [
        ("Length: 8+ characters", True),
        ("Length: 12+ characters (+40 pts)", False),
        ("Contains uppercase & lowercase letters", True),
        ("Contains numbers", True)
    ])])),
    Page(
        State(
            current_password="",
            history=[PasswordRecord("Secr******", 70, "Strong", [
                ("Length: 8+ characters", True),
                ("Length: 12+ characters (+40 pts)", False),
                ("Contains uppercase & lowercase letters", True),
                ("Contains numbers", True)
            ])],
            is_strict=False,
            active_category="Personal"
        ),
        [
            styled_page_container(
                Header("Results", 2),
                Header("Score: 70 / 100 (Strong)", 3),
                Paragraph("Evaluated Password: Secr******"),
                Header("Condition Breakdown", 4),
                BulletedList([
                    "✅ Length: 8+ characters",
                    "❌ Length: 12+ characters (+40 pts)",
                    "✅ Contains uppercase & lowercase letters",
                    "✅ Contains numbers"
                ]),
                LineBreak(),
                Row(
                    Button("Test Another", analyzer),
                    Button("View Past Passwords", history),
                    Button("Back to Home", index),
                ),
            )
        ],
    ),
)

# Unit test for the history route to ensure correct page rendering and state management
assert_equal(
    history(State(history=[PasswordRecord("Secr******", 70, "Strong", [
        ("Length: 8+ characters", True),
        ("Length: 12+ characters (+40 pts)", False),
        ("Contains uppercase & lowercase letters", True),
        ("Contains numbers", True)
    ])])),
    Page(
        State(
            current_password="",
            history=[PasswordRecord("Secr******", 70, "Strong", [
                ("Length: 8+ characters", True),
                ("Length: 12+ characters (+40 pts)", False),
                ("Contains uppercase & lowercase letters", True),
                ("Contains numbers", True)
            ])],
            is_strict=False,
            active_category="Personal"
        ),
        [
            styled_page_container(
                Header("Audit History", 2),
                BulletedList([
                    "Password: Secr****** | Score: 70 (Strong)"
                ]),
                LineBreak(),
                Button("Return Home", index),
            )
        ],
    ),
)   

# Unit test for the tips route to ensure correct page rendering and state management
assert_equal(
    tips(State()),
    Page(
        State(
            current_password="",
            history=[],
            is_strict=False,
            active_category="Personal"
        ),
        [
            styled_page_container(
                Header("Security Tips", 2),
                Paragraph("1. Use passphrases combining 4+ random words."),
                Paragraph("2. Avoid reusing passwords across critical services."),
                LineBreak(),
                Button("Back to Home", index),
            )
        ],
    ),
)

# Unit test for the about route to ensure correct page rendering and state management
assert_equal(
    about(State()),
    Page(
        State(
            current_password="",
            history=[],
            is_strict=False,
            active_category="Personal"
        ),
        [
            styled_page_container(
                Header("About PassGuard", 2),
                Paragraph(
                    "PassGuard is engineered using the Drafter framework and Python dataclasses "
                    "to provide real-time cryptographic strength assessment and session-based audit logging."
                ),
                LineBreak(),
                Button("Back to Home", index),
            )
        ],
    ),
)   



# Start the server with initial state instance
start_server(State(), open_browser = False)
