package Acknowledgement;

use strict;
use File::Slurp;
use Try::Tiny;
use Carp qw/croak/;
use Data::Dumper;
use POSIX qw(strftime);
use Text::CSV_XS;

sub new {
    my $this = shift;
    my $class = ref($this) || $this;
    my $self = {};
    bless ($self,$class);
    return $self;
}

sub acknowledge {
    my $self = shift;
    ($self->{'gcn'}, $self->{'file'}, $self->{'fh'}) = @{{@_}}{qw/gcn file fh/};
    $self->_validate_args;

    $self->{'edi'} = try { read_file( $self->{'file'} )} catch {croak "Failed reading EDI file: ",$_};
    $self->{'csv'} = try {

        Text::CSV_XS->new(
        {
            'binary'     => 1,
            'sep_char'   => qq{*},
            'eol'        => qq{~},
            'quote_char' => undef,
        });
    }
    catch {
        croak "Failed creating CSV_XS instance: ",$_
    };
    $self->{'set_count'} = 0;
    $self->{'is997'} = 0;

    $self->_scrub_EDI;
    $self->_check_997 and return;
    $self->_validate_EDI;
    $self->_generate_header;
    $self->_generate_groups;
    $self->_close_ack;

}

sub _scrub_EDI {
    my $self = shift;
    # Remove end-line characters and 997s
    $self->{'edi'} =~ s/…||\r\n|\n/~/g; 
    $self->{'edi'} =~ s/~ST\*997.*?SE\*[1-9].*?~/~/g; 
}

sub _generate_header {
    my $self = shift;
    
    my ($short_date,$long_date,$time) = (strftime('%y%m%d',localtime),strftime('%Y%m%d',localtime),strftime('%H%M',localtime));

    my $ISA = (grep(/^ISA\*/, split(/\~/,$self->{'edi'}) ))[0];
    my ($sender_qual,$sender,$receiver_qual,$receiver,$doc_id) = (split (/\*/,$ISA))[5,6,7,8,13];
    my $isa_id = $self->{'gcn'};
    $isa_id = '0' . $isa_id while length($isa_id) < 9;
    my @isa = ('ISA','00','          ','00','          ',$receiver_qual,$receiver,$sender_qual,$sender,$short_date,$time,'U','00401',"$isa_id",'0','P','>');
    $receiver =~ s/\ //g;
    $sender =~ s/\ //g;

    my $GS = (grep(/GS\*/, split(/\~/,$self->{'edi'}) ))[0];
    my $gsSender = (split /\*/,$GS)[2];

    my @gs = ('GS','FA',$receiver,$gsSender,$long_date,$time,$self->{'gcn'},'X','004010');

    $self->{'csv'}->print($self->{'fh'},\@isa); 
    $self->{'csv'}->print($self->{'fh'},\@gs); 
}

sub _generate_groups {
    my $self = shift;
    my $edi = $self->{'edi'};
    $edi =~ s/^ISA\*.*?~|IEA\*.*?~|GS\*FA.*?~|GE\*.*?~//g;
    
    my @GSs = grep (/GS\*/, split(/~/,$edi));

    my $index = 0;
    foreach my $set (split (/GS\*.*?~|GE\*.*?~/,$edi)) {
        next unless $set;
        my ($grp_code,$grp_cntrl_num) = (split (/\*/,@GSs[$index++]))[1,6];

        my @STs = grep (/^ST\*/,split(/\~/,$set));

        foreach (@STs) {
            $self->_generate_set($grp_code,$grp_cntrl_num,$_);
        }
    }
}

sub _generate_set {
    my $self = shift;
    my ($grp_code,$grp_cntrl_num,$st) = @_;
    my $cntrl_num = ( split (/\*/,$st) )[2];
    my @ST = ('ST','997',"$cntrl_num");
    my @AK1 = ('AK1',"$grp_code","$grp_cntrl_num");
    my @AK9 = ('AK9','A','1','1','1');
    my @SE = ('SE','4',"$cntrl_num");
    $self->{'csv'}->print($self->{'fh'},\@ST);
    $self->{'csv'}->print($self->{'fh'},\@AK1);
    $self->{'csv'}->print($self->{'fh'},\@AK9);
    $self->{'csv'}->print($self->{'fh'},\@SE);
    $self->{'set_count'}++;
}

sub _close_ack {
    my $self = shift;
    my $isa_id = $self->{'gcn'};
    $isa_id = '0' . $isa_id while length($isa_id) < 9;
    my @GE = ('GE',$self->{'set_count'},"$isa_id"); 
    my @IE = ('IEA','1',$isa_id);
    $self->{'csv'}->print($self->{'fh'},\@GE);
    $self->{'csv'}->print($self->{'fh'},\@IE);

    1;
}

sub _validate_args {
    my $self = shift;
    my $errors = "";

    $self->{'gcn'} or $errors .= "Group control number (gcn) not provided.";
    -f $self->{'file'} or $errors .= "Invalid or missing file argument (file)";
    tell ($self->{'fh'}) >= 0 or $errors .= "Invalid or missing file handle argument (fh)"; 

    !$errors or croak $errors;
}

sub _validate_EDI {
    my $self = shift;
    my $errors = "";

    # Check ISA heaer
    my $ISA = (grep(/^ISA\*/, split(/\~/,$self->{'edi'}) ))[0];
    $ISA or $errors .= "Missing ISA header in file " . $self->{'file'} . "\n";
    my ($sender_qual,$sender,$receiver_qual,$receiver,$doc_id) = (split (/\*/,$ISA))[5,6,7,8,13];
    $sender_qual or $errors .= "Missing sender qualifier in file " . $self->{'file'} . "\n";
    $sender or $errors .= "Missing sender ID in file " . $self->{'file'} . "\n";
    length($sender_qual) == 2 or $errors .= "Invalid sender qualifier in file " . $self->{'file'} . "\n";
    length($sender) == 15 or $errors .= "Invalid sender ID in file " . $self->{'file'} . "\n";
    $receiver_qual or $errors .= "Missing receiver qualifier in file " . $self->{'file'} . "\n";
    $receiver or $errors .= "Missing receiver ID in file " . $self->{'file'} . "\n";
    length($receiver_qual) == 2 or $errors .= "Invalid receiver qualifier in file " . $self->{'file'} . "\n";
    length($receiver) == 15 or $errors .= "Invalid receiver ID in file " . $self->{'file'} . "\n";
    $doc_id or $errors .= "Missing document ID in file " . $self->{'file'} . "\n";
    length($doc_id) == 9 or $errors .= "Invalid document ID in file " . $self->{'file'} . "\n";

    # Check group and transaction sets
    my $edi = $self->{'edi'};
    $edi =~ s/^ISA\*.*?~|IEA\*.*?~|GS\*FA.*?~|GE\*.*?~//g;
    my @GSs = grep (/GS\*/, split(/~/,$edi));
    @GSs or $errors .= "Missing group sets in file " . $self->{'file'} . "\n";

    my $index = 0;
    foreach my $set (split (/GS\*.*?~|GE\*.*?~/,$edi)) {
        next unless $set;
        my ($grp_code,$grp_cntrl_num) = (split (/\*/,@GSs[$index++]))[1,6];
        $grp_code or $errors .= "Missing group qualifier in file " . $self->{'file'} . "\n";
        $grp_cntrl_num or $errors .= "Missing group control number in file " . $self->{'file'} . "\n";

        my @STs = grep (/^ST\*/,split(/\~/,$set));

        foreach (@STs) {
            my $cntrl_num = ( split (/\*/,$_) )[2];
            $cntrl_num or $errors .= "Missing set control number in file " . $self->{'file'} . "\n";

        }
    }

    !$errors or croak $errors;
}

sub _check_997 {
    my $self = shift;
    my $edi = $self->{'edi'};
    $edi =~ s/^ISA\*.*?~|IEA\*.*?~|IE\*.*?~|GS\*FA.*?~|GE\*.*?~//g;
    $edi or $self->{'is997'} = 1;
    return $self->{'is997'};
}

1;