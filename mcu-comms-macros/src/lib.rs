use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Type};

#[proc_macro_attribute]
pub fn payload(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input: DeriveInput = syn::parse(item).unwrap();
    let name = &input.ident;

    let field_sizes = field_sizes(&input.data);

    let expanded = quote! {
        #[derive(
            ::mcu_comms::serde::Serialize,
            ::mcu_comms::serde::Deserialize,
        )]
        #[serde(crate = "::mcu_comms::serde")]
        #input

        impl ::mcu_comms::payload_size::MaxSize for #name {
            const MAX_SIZE: usize = 0 #(+ #field_sizes)*;
        }
        impl ::mcu_comms::payload_size::MaxPayloadSize for #name {
            const FRAME_SIZE: usize = <#name as ::mcu_comms::payload_size::MaxSize>::MAX_SIZE
                + ::mcu_comms::aesccm::HEADER_SIZE
                + ::mcu_comms::aesccm::TAG_SIZE;
            type FrameBuf = [u8; Self::FRAME_SIZE];
            fn new_buf() -> Self::FrameBuf {
                [0_u8; Self::FRAME_SIZE]
            }
        }
        impl ::mcu_comms::payload_size::Payload for #name {}
    };
    expanded.into()
}

fn field_sizes(data: &syn::Data) -> Vec<TokenStream2> {
    let field_sizes = match data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields
                .named
                .iter()
                .map(|f| {
                    let ty = &f.ty;
                    panic_if_uisize(&ty);
                    quote! { <#ty as ::mcu_comms::payload_size::MaxSize>::MAX_SIZE }
                })
                .collect(),
            Fields::Unnamed(fields) => fields
                .unnamed
                .iter()
                .map(|f| {
                    let ty = &f.ty;
                    panic_if_uisize(&ty);
                    quote! {<#ty as ::mcu_comms::payload_size::MaxSize>::MAX_SIZE}
                })
                .collect(),
            Fields::Unit => vec![],
        },
        Data::Enum(data) => {
            let variant_sizes: Vec<TokenStream2> = data
                .variants
                .iter()
                .map(|v| {
                    let field_sizes: Vec<TokenStream2> = v
                        .fields
                        .iter()
                        .map(|f| {
                            let ty = &f.ty;
                            panic_if_uisize(&ty);
                            quote! { <#ty as ::mcu_comms::payload_size::MaxSize>::MAX_SIZE }
                        })
                        .collect();
                    quote! { (0 #(+ #field_sizes)*) }
                })
                .collect();

            vec![quote! {{
                const fn max(a: usize, b: usize) -> usize {
                    if a > b { a } else { b }
                }
                let mut m = 0;
                #( m = max(m, #variant_sizes); )*
                m + 5
            }}]
        }
        _ => panic!("Payload does not support this type"),
    };
    field_sizes
}

fn panic_if_uisize(ty: &Type) {
    if let syn::Type::Path(p) = ty {
        if let Some(seg) = p.path.segments.last() {
            if seg.ident == "usize" || seg.ident == "isize" {
                panic!(
                    "usize/isize are not portable across differing pointer-width targets in payload structs — use a fixed-width type like u32 or u64 instead"
                );
            }
        }
    }
}
