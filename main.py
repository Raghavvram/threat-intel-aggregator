import streamlit as st
import json
from modules.feed_handler import fetch_feeds
from modules.ioc_extractor import extract_iocs
from modules.summarizer import generate_summary
from config import FEEDS, OLLAMA_MODEL


def get_ioc_stats(iocs_data):
    if not iocs_data or not isinstance(iocs_data, dict):
        return "No IOCs extracted"
    
    total_iocs = 0
    for key, value in iocs_data.items():
        if key == 'hashes' and isinstance(value, dict):
            total_iocs += sum(len(h_list) for h_list in value.values())
        elif isinstance(value, list):
            total_iocs += len(value)
    
    categories = len(iocs_data)
    return f"🎯 {total_iocs} IOCs across {categories} categories"


def load_and_process_feeds():
    with st.spinner("Fetching and processing feeds..."):
        articles = fetch_feeds(FEEDS)
        if not articles:
            st.session_state.articles = []
            st.session_state.article_titles = []
            st.warning("⚠️ No articles found. Please check feed URLs or network connection.")
            return

        st.session_state.articles = articles
        st.session_state.article_titles = [
            f"{article['published_str']} | {article['title']} ({article['source']})" for article in articles
        ]
        st.info(f"📊 {len(articles)} threat reports loaded")


def main():
    st.set_page_config(
        layout="wide",
        page_title="Threat Intelligence Hub"
    )

    if 'articles' not in st.session_state:
        st.session_state.articles = []
        st.session_state.article_titles = []

    st.markdown("# 🛡️ Threat Intelligence Hub")
    st.markdown("AI-Powered Threat Analysis & IOC Extraction")
    
    header_col1, header_col2 = st.columns([1, 4])

    with header_col1:
        if st.button("🔄 Refresh Threat Feeds", use_container_width=True, type="primary"):
            load_and_process_feeds()

    with header_col2:
        st.markdown(f"**Model:** `{OLLAMA_MODEL}`", unsafe_allow_html=True)
    
    st.divider()

    if not st.session_state.articles:
        load_and_process_feeds()

    col1, col2 = st.columns([2, 3])

    with col1:
        st.markdown("## 📋 Threat Reports")
        
        selected_title = st.selectbox(
            label="Select Report to Analyze",
            options=st.session_state.article_titles,
            index=0 if st.session_state.article_titles else None,
            label_visibility="collapsed"
        )
        
        article_details_placeholder = st.container()
        
        st.markdown("## 🎯 Indicators of Compromise")
        ioc_stats_placeholder = st.empty()
        iocs_output_placeholder = st.empty()

    with col2:
        st.markdown("## 🤖 AI Threat Analysis")
        summary_output_placeholder = st.empty()


    if not selected_title:
        summary_output_placeholder.info("Select a threat report to view AI-generated analysis.")
        ioc_stats_placeholder.markdown("No IOCs extracted yet")
        return

    selected_article = next(
        (article for article in st.session_state.articles 
         if f"{article['published_str']} | {article['title']} ({article['source']})" == selected_title), 
        None
    )

    if selected_article:
        with st.spinner(f"Analyzing: {selected_article['title']}"):
            summary = generate_summary(selected_article['content'], OLLAMA_MODEL)
            iocs = extract_iocs(selected_article['content'])
            filtered_iocs = {k: v for k, v in iocs.items() if v}
            ioc_stats_text = get_ioc_stats(filtered_iocs)
            
            article_card = f"""
            ### [{selected_article['title']}]({selected_article['link']})
            **Source:** {selected_article['source']} | **Published:** {selected_article['published_str']}
            """
            
            with article_details_placeholder:
                st.markdown(article_card, unsafe_allow_html=True)
            
            summary_output_placeholder.markdown(summary, unsafe_allow_html=True)
            ioc_stats_placeholder.markdown(ioc_stats_text)

            if filtered_iocs:
                iocs_output_placeholder.json(filtered_iocs)
            else:
                iocs_output_placeholder.info("No IOCs were extracted from this report.")


if __name__ == "__main__":
    main()