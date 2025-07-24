import gradio as gr
import json
from modules.feed_handler import fetch_feeds
from modules.ioc_extractor import extract_iocs
from modules.summarizer import generate_summary
from config import FEEDS, OLLAMA_MODEL


def process_and_load_feeds():
    print("Fetching and processing feeds...")
    articles = fetch_feeds(FEEDS)
    
    if not articles:
        return (
            [], 
            gr.update(choices=[], value=None), 
            "⚠️ No articles found. Please check feed URLs or network connection.",
            {},
            "",
            "No threat reports available",
            0
        )
    
    article_titles = [f"{article['published_str']} | {article['title']} ({article['source']})" for article in articles]
    print(f"Fetched {len(articles)} articles.")
    
    summary, iocs, details = analyze_article(article_titles[0], articles)
    
    return (
        articles, 
        gr.update(choices=article_titles, value=article_titles[0]), 
        summary, 
        iocs, 
        details,
        f"📊 {len(articles)} threat reports loaded",
        len(articles)
    )


def analyze_article(selected_title, articles_state):
    if not selected_title or not articles_state:
        return "Select an article to view AI analysis.", {}, ""
    
    selected_article = next(
        (article for article in articles_state 
         if f"{article['published_str']} | {article['title']} ({article['source']})" == selected_title), 
        None
    )
    
    if not selected_article:
        return "❌ Article not found.", {}, ""
    
    print(f"Analyzing: {selected_article['title']}")
    
    summary = generate_summary(selected_article['content'], OLLAMA_MODEL)
    iocs = extract_iocs(selected_article['content'])
    
    filtered_iocs = {k: v for k, v in iocs.items() if v}
    
    article_card = f"""
    <div style="border-left: 4px solid #3b82f6; padding: 16px; background: #f8fafc; border-radius: 8px; margin: 8px 0;">
        <h3 style="margin: 0 0 8px 0; color: #1e40af;">
            <a href="{selected_article['link']}" target="_blank" style="text-decoration: none; color: inherit;">
                {selected_article['title']} ↗
            </a>
        </h3>
        <div style="display: flex; gap: 16px; font-size: 14px; color: #64748b;">
            <span><strong>Source:</strong> {selected_article['source']}</span>
            <span><strong>Published:</strong> {selected_article['published_str']}</span>
        </div>
    </div>
    """
    
    return summary, filtered_iocs, article_card


def get_ioc_stats(iocs_data):
    if not iocs_data:
        return "No IOCs extracted"
    
    total_iocs = 0
    if isinstance(iocs_data, dict):
        for key, value in iocs_data.items():
            if key == 'hashes' and isinstance(value, dict):
                total_iocs += sum(len(h_list) for h_list in value.values())
            elif isinstance(value, list):
                total_iocs += len(value)
    
    categories = len(iocs_data)
    
    return f"🎯 {total_iocs} IOCs across {categories} categories"


def create_dashboard():
    with gr.Blocks(
        theme=gr.themes.Soft(),
        title="Threat Intel Aggregator"
    ) as dashboard:
        
        articles_state = gr.State([])
        
        gr.Markdown("# 🛡️ Threat Intelligence Hub")
        gr.Markdown("AI-Powered Threat Analysis & IOC Extraction")
        
        with gr.Row():
            refresh_button = gr.Button("🔄 Refresh Threat Feeds", variant="primary")
            status_display = gr.Markdown("Click refresh to load reports")
            model_info = gr.Markdown(f"**Model:** `{OLLAMA_MODEL}`")
        
        with gr.Row(equal_height=False):
            with gr.Column(scale=2, min_width=400):
                with gr.Group():
                    gr.Markdown("## 📋 Threat Reports")
                    article_dropdown = gr.Dropdown(
                        label="Select Report to Analyze",
                        interactive=True
                    )
                    article_details = gr.HTML("")
                
                with gr.Group():
                    gr.Markdown("## 🎯 Indicators of Compromise")
                    ioc_stats = gr.Markdown("No IOCs extracted yet")
                    iocs_output = gr.JSON(label="Extracted IOCs")
            
            with gr.Column(scale=3, min_width=500):
                with gr.Group():
                    gr.Markdown("## 🤖 AI Threat Analysis")
                    summary_output = gr.Markdown(
                        "Select a threat report to view AI-generated analysis.",
                        elem_id="summary-output",
                        line_breaks=True,
                    )
        
        def update_ui_after_analysis(selected_title, articles_state):
            summary, iocs, details = analyze_article(selected_title, articles_state)
            ioc_stats_text = get_ioc_stats(iocs)
            return summary, iocs, details, ioc_stats_text
        
        refresh_button.click(
            fn=process_and_load_feeds,
            inputs=[],
            outputs=[
                articles_state, 
                article_dropdown, 
                summary_output, 
                iocs_output, 
                article_details,
                status_display,
                gr.State()
            ]
        ).then(
            fn=lambda iocs: get_ioc_stats(iocs),
            inputs=[iocs_output],
            outputs=[ioc_stats]
        )
        
        article_dropdown.change(
            fn=update_ui_after_analysis,
            inputs=[article_dropdown, articles_state],
            outputs=[summary_output, iocs_output, article_details, ioc_stats]
        )
        
        dashboard.load(
            fn=process_and_load_feeds,
            inputs=[],
            outputs=[
                articles_state, 
                article_dropdown, 
                summary_output, 
                iocs_output, 
                article_details,
                status_display,
                gr.State()
            ]
        ).then(
            fn=lambda iocs: get_ioc_stats(iocs),
            inputs=[iocs_output],
            outputs=[ioc_stats]
        )
    
    return dashboard


if __name__ == "__main__":
    app = create_dashboard()
    app.launch()