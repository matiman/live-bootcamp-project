use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn with_cleanup(_: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);
    let name = &func.sig.ident;
    let body = &func.block;
    let attrs = &func.attrs;

    quote! {
        #(#attrs)*
        #[tokio::test]
        async fn #name() {
            let app = crate::helpers::TestApp::new().await;
            #body
            app.clean_up().await;
        }
    }
    .into()
}
